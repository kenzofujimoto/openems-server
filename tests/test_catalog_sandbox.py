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
    report = {"run_id": manifest["run_id"], "source_revision": manifest["source_revision"],
            "status": "passed", "passed": True, "error": None, "cleanup_errors": [],
            "package_receipt": {"source_revision": manifest["source_revision"], "packages": manifest["packages"],
                                "manifest_sha256": manifest["_manifest_sha256"]},
            "checks": [{"name": name, "status": "passed", "evidence": evidence[name]} for name in CHECKS]}
    if manifest.get("evidence_format") == 2:
        add_v2_evidence(report, manifest)
    return report


def firewall_rule(name="foreign-rule", *, enabled="True", direction="Inbound", action="Allow"):
    return {"name": name, "enabled": enabled, "direction": direction, "action": action}


def firewall_snapshot(rules=None, *, at_utc="2026-11-02T15:59:58Z"):
    rules = [firewall_rule()] if rules is None else deepcopy(rules)
    return {"status": "complete", "at_utc": at_utc, "rules": rules, "error": None,
            "truncated": False, "observed_count": len(rules)}


def add_v2_evidence(report, manifest):
    """Supply observed values, never let a passed flag replace raw observations."""
    before = firewall_snapshot()
    after = firewall_snapshot(at_utc="2026-11-02T17:01:00Z")
    report.update(evidence_format=2, firewall_before=deepcopy(before), ack_observations=[
        {key: assignment[key] for key in ("version", "digest")} |
        {"success": True, "at_utc": "2026-11-02T16:00:00Z", "error_kind": None}
        for assignment in manifest["policies"].values()
    ])
    cleanup = next(row["evidence"] for row in report["checks"] if row["name"] == "cleanup")
    cleanup.update(collection_status="complete", collection_errors=[], firewall={
        "before": before, "after": after, "differences": [], "preserved": True,
    })
    return report


def direct_v2_manifest():
    return {
        "run_id": RUN_ID, "source_revision": REVISION, "_manifest_sha256": "d" * 64,
        "evidence_format": 2, "guest_work_directory": "C:\\openems-catalog-" + RUN_ID,
        "fixtures": {"a": {"file": "a.exe"}},
        "packages": {"openems-agent.msi": {"sha256": "e" * 64, "bytes": 1}},
        "policies": {name: {"version": index + 1, "digest": "c" * 64}
                     for index, name in enumerate(CASES)},
    }


def v2_mutation(report, change):
    report = deepcopy(report)
    for apply in (mutate_v2_snapshot, mutate_v2_firewall, mutate_v2_metadata):
        if apply(report, change):
            return report
    raise AssertionError("Unknown v2 mutation: " + change)


def mutate_v2_snapshot(report, change):
    cleanup = report["checks"][-1]["evidence"]
    firewall = cleanup["firewall"]
    if change == "missing_firewall":
        del cleanup["firewall"]
    elif change == "missing_baseline":
        del report["firewall_before"]
    elif change == "baseline_replaced":
        firewall["before"]["rules"][0]["name"] = "unbound-baseline"
    elif change == "missing_after":
        del firewall["after"]
    elif change == "query_failed":
        firewall["after"].update(status="failed", error="firewall_query_failed")
    elif change == "truncated":
        firewall["after"].update(status="truncated", truncated=True, observed_count=2)
    elif change == "truncated_flag":
        firewall["after"]["truncated"] = True
    elif change == "missing_rule_count":
        del firewall["after"]["observed_count"]
    elif change == "wrong_rule_count":
        firewall["after"]["observed_count"] += 1
    elif change == "boolean_rule_count":
        firewall["after"]["observed_count"] = True
    elif change == "invalid_timestamp":
        firewall["after"]["at_utc"] = "not-a-timestamp"
    elif change == "error_on_complete":
        firewall["after"]["error"] = "firewall_query_failed"
    else:
        return False
    return True


def mutate_v2_firewall(report, change):
    firewall = report["checks"][-1]["evidence"]["firewall"]
    if change == "removed_rule":
        firewall["after"]["rules"] = []
        firewall["after"]["observed_count"] = 0
    elif change == "changed_enabled":
        firewall["after"]["rules"][0]["enabled"] = "False"
    elif change == "changed_direction":
        firewall["after"]["rules"][0]["direction"] = "Outbound"
    elif change == "changed_action":
        firewall["after"]["rules"][0]["action"] = "Block"
    elif change == "duplicate_after":
        firewall["after"]["rules"] *= 2
        firewall["after"]["observed_count"] = 2
    elif change == "false_preserved":
        firewall["preserved"] = False
    elif change == "coerced_preserved":
        firewall["preserved"] = 1
    elif change == "fabricated_difference":
        firewall["differences"] = [{"name": "foreign-rule", "kind": "changed", "fields": ["enabled"]}]
    elif change == "unrecorded_addition":
        firewall["after"]["rules"].append(firewall_rule("new-rule"))
        firewall["after"]["observed_count"] += 1
    elif change == "invalid_enum":
        firewall["after"]["rules"][0]["enabled"] = 1
    elif change == "empty_rule_name":
        firewall["after"]["rules"][0]["name"] = ""
    else:
        return False
    return True


def mutate_v2_metadata(report, change):
    cleanup = report["checks"][-1]["evidence"]
    if change == "partial_cleanup":
        cleanup["collection_status"] = "partial"
    elif change == "query_error_in_cleanup":
        cleanup["collection_errors"] = [{"field": "service_present", "error": "query_failed"}]
    elif change == "missing_cleanup_status":
        del cleanup["collection_status"]
    elif change == "missing_acks":
        del report["ack_observations"]
    elif change == "foreign_ack_identity":
        report["ack_observations"][0]["digest"] = "f" * 64
    elif change == "ack_raw_detail":
        report["ack_observations"][0]["error"] = "unexpected raw diagnostic text"
    elif change == "ack_invalid_timestamp":
        report["ack_observations"][0]["at_utc"] = "not-a-timestamp"
    elif change == "missing_version":
        del report["evidence_format"]
    elif change == "downgrade":
        report["evidence_format"] = 1
    else:
        return False
    return True


V2_INVALID = (
    "missing_firewall", "missing_baseline", "baseline_replaced", "missing_after", "query_failed",
    "truncated", "truncated_flag", "missing_rule_count", "wrong_rule_count", "boolean_rule_count",
    "invalid_timestamp", "error_on_complete", "removed_rule", "changed_enabled", "changed_direction",
    "changed_action", "duplicate_after", "false_preserved", "coerced_preserved", "fabricated_difference",
    "unrecorded_addition", "invalid_enum", "empty_rule_name", "partial_cleanup", "query_error_in_cleanup",
    "missing_cleanup_status", "missing_acks", "foreign_ack_identity", "ack_raw_detail",
    "ack_invalid_timestamp", "missing_version", "downgrade",
)


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


def test_new_catalog_packages_require_evidence_v2_without_relabelling_legacy(builder, package):
    output, manifest = package()
    assert manifest.get("evidence_format") == 2, "new media must require persisted cleanup evidence"
    assert builder.verify_package(output)["evidence_format"] == 2


@pytest.mark.parametrize("change", V2_INVALID)
def test_v2_host_recomputes_firewall_and_refuses_incomplete_cleanup_despite_passed_flags(builder, change):
    manifest = direct_v2_manifest()
    report = v2_mutation(report_for(manifest), change)
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is False and summary["errors"], summary


@pytest.mark.parametrize("kind", ["unchanged", "empty", "added", "case_only"])
def test_v2_host_preserves_the_original_firewall_guard_semantics(builder, kind):
    manifest = direct_v2_manifest()
    report = report_for(manifest)
    firewall = report["checks"][-1]["evidence"]["firewall"]
    if kind == "empty":
        before, after = firewall_snapshot([]), firewall_snapshot([], at_utc="2026-11-02T17:01:00Z")
        report["firewall_before"] = deepcopy(before)
        firewall.update(before=before, after=after)
    elif kind == "added":
        firewall["after"]["rules"].append(firewall_rule("new-rule"))
        firewall["after"]["observed_count"] += 1
        firewall["differences"] = [{"name": "new-rule", "kind": "added", "fields": []}]
    elif kind == "case_only":
        firewall["after"]["rules"][0]["name"] = "FOREIGN-RULE"
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is True and summary["errors"] == [], summary


@pytest.mark.parametrize("error_kind", ["OSError", "LocalError", "unknown"])
def test_v2_host_exposes_negative_ack_observations_without_replacing_the_eight_effects(builder, error_kind):
    manifest = direct_v2_manifest()
    report = report_for(manifest)
    failed = {**report["ack_observations"][5], "success": False, "error_kind": error_kind}
    report["ack_observations"].insert(6, failed)
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is True and summary["local_enforcement_failures"] == [failed], summary


def test_v2_failed_flags_do_not_hide_the_missing_firewall_evidence(builder):
    manifest = direct_v2_manifest()
    report = v2_mutation(report_for(manifest), "missing_firewall")
    report.update(status="failed", passed=False)
    summary = builder.summarize_report(report, manifest)
    assert not summary["passed"] and any("firewall" in error.lower() for error in summary["errors"]), summary


@pytest.mark.parametrize("explicit", [False, True])
def test_v1_evidence_keeps_its_original_contract_without_v2_claims(builder, explicit):
    manifest = direct_v2_manifest()
    manifest.pop("evidence_format")
    report = report_for(manifest)
    if explicit:
        manifest["evidence_format"] = 1
        report["evidence_format"] = 1
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is True, summary


PURE_DRIVER = r"""param([string]$Source,[string]$DataPath,[string]$ExpressionPath,[string]$Names)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Catalog harness did not parse.' }
foreach($name in (@('Field','Compare-FirewallSnapshots') + @($Names -split ',') | Select-Object -Unique)) {
    $matches=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
    if($name -in @('Field','Compare-FirewallSnapshots') -and $matches.Count -eq 0 -and $name -notin @($Names -split ',')) { continue }
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
function global:Get-NetFirewallRule { throw 'Forbidden host endpoint query: firewall' }
function global:Get-Service { throw 'Forbidden host endpoint query: service' }
function global:Get-ScheduledTask { throw 'Forbidden host endpoint query: task' }
function global:Get-DnsClientNrptRule { throw 'Forbidden host endpoint query: NRPT' }
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


def isolated(tmp_path, functions, expression, data, commands=(), *, callbacks=(), methods=()):
    # Check actual selected helper bodies before invocation; every endpoint query
    # has a mock in the expression. Loading the harness top-level is forbidden.
    allowed = sorted(set(functions) | set(commands) | {
        "Field", "Where-Object", "Select-Object", "ForEach-Object", "Sort-Object", "ConvertTo-Json",
        "ConvertFrom-Json", "Compare-FirewallSnapshots", "Add-Member", "Write-Output",
    })
    guard = r"""
$safeCommands=__ALLOWED__
$safeCallbacks=__CALLBACKS__
$safeMethods=__METHODS__
$selectedFunctions=@($tree.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @($Names -split ',')
},$true))
foreach($definition in $selectedFunctions){
    $nested=@($definition.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | ForEach-Object Name)
    foreach($command in @($definition.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
        if($command.GetCommandName() -in ($safeCommands+$nested)){continue}
        $first=$command.CommandElements[0]
        if($command.InvocationOperator -eq 'Ampersand' -and
            $first -is [Management.Automation.Language.VariableExpressionAst] -and
            $first.VariablePath.UserPath -in $safeCallbacks){continue}
        throw 'Unmocked command in isolated helper.'
    }
    foreach($method in @($definition.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true))){
        if($method.Member.Value -notin ($safeMethods+@('ToString','Contains','ContainsKey','Add','GetEnumerator','GetType','Equals','Parse','ToUniversalTime','ToLowerInvariant'))){
            throw 'Unexpected method in isolated helper.'
        }
    }
}
"""
    for key, values in (("__ALLOWED__", allowed), ("__CALLBACKS__", callbacks), ("__METHODS__", methods)):
        guard = guard.replace(key, "@(" + ",".join("'" + name + "'" for name in values) + ")")
    return pure(tmp_path, functions, "$global:catalogTestData=$fixtureData\n" + guard + expression, data)


def startup_sample(duration_ms, *, marker=False, exited=False, error=False):
    return {"duration_ms": duration_ms, "marker": marker, "exited": exited, "error": error}


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("samples,pauses,status,last_ms,terminal_ms", [
    pytest.param([startup_sample(1, marker=True)], [], "started", 1, None, id="immediate"),
    pytest.param([startup_sample(9999, marker=True)], [], "started", 9999, None, id="before-deadline"),
    pytest.param([startup_sample(10000, marker=True)], [], "timeout", None, 10000, id="exact-deadline"),
    pytest.param([startup_sample(1), startup_sample(9800, marker=True)], [300],
                 "timeout", 1, 10101, id="slow-predicate"),
    pytest.param([startup_sample(0), startup_sample(1, marker=True)], [11500],
                 "timeout", 0, 11501, id="pause-misses-window"),
    pytest.param([startup_sample(20, exited=True)], [], "exited", 20, None, id="exit-before-marker"),
    pytest.param([startup_sample(20, marker=True, exited=True)], [], "started", 20, None, id="marker-and-exit"),
    pytest.param([startup_sample(0), startup_sample(1, error=True)], [11500],
                 "timeout", 0, 11501, id="terminal-query-fails"),
])
def test_fixture_startup_clock_rejects_terminal_observations_as_success(tmp_path, samples, pauses, status,
                                                                 last_ms, terminal_ms):
    expression = r"""
$global:startupClock=0;$global:startupReads=0;$global:startupPauses=0
$observe={
    $item=$global:catalogTestData.samples[$global:startupReads]
    $global:startupReads++
    if($null -eq $item){throw 'Unexpected additional observation.'}
    $global:startupClock+=$item.duration_ms
    if($item.error){throw 'synthetic-private-query-error'}
    return @{marker_present=$item.marker;process_exited=$item.exited}
}
$pause={
    $delta=$global:catalogTestData.pauses[$global:startupPauses]
    $global:startupPauses++
    if($null -eq $delta){throw 'Unexpected additional wait.'}
    $global:startupClock+=$delta
}
$observed=Wait-FixtureStartup $observe {$global:startupClock} $pause
if($observed.status -cne $fixtureData.status -or $observed.elapsed_ms -ne $global:startupClock -or
   $global:startupReads -ne @($fixtureData.samples).Count -or $global:startupPauses -ne @($fixtureData.pauses).Count){
    throw 'The startup window changed or read more than once after the deadline.'
}
if($null -eq $fixtureData.last_ms){
    if($null -ne $observed.last_in_window){throw 'A late sample was marked within the window.'}
}elseif($observed.last_in_window.at_ms -ne $fixtureData.last_ms){
    throw 'The last in-window sample time must come from the end of its read.'
}
if($null -eq $fixtureData.terminal_ms){
    if($null -ne $observed.terminal){throw 'An on-time result should not require a terminal read.'}
}else{
    if($observed.terminal.at_ms -ne $fixtureData.terminal_ms){throw 'The terminal observation lost its monotonic time.'}
    $lastSample=$fixtureData.samples[-1]
    if($lastSample.error){
        if($observed.terminal.error_kind -cne 'query_failed' -or $null -ne $observed.terminal.marker_present -or
            $null -ne $observed.terminal.process_exited){throw 'A failed read reported a definite state.'}
    }elseif($observed.terminal.marker_present -ne $lastSample.marker){
        throw 'A terminal observation did not preserve the late marker.'
    }
}
if($fixtureData.status -ceq 'started' -and $observed.last_in_window.marker_present -isnot [bool]){
    throw 'An observed marker must retain its type.'
}
"""
    observed = isolated(tmp_path, ["Wait-FixtureStartup"], expression, {
        "samples": samples, "pauses": pauses, "status": status, "last_ms": last_ms, "terminal_ms": terminal_ms,
    }, ["Start-Sleep"], callbacks=("Observe", "ElapsedMilliseconds", "Pause"))
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
def test_fixture_startup_records_unavailable_sample_without_inventing_marker_or_exit(tmp_path):
    expression = r"""
$observed=Wait-FixtureStartup {throw 'synthetic-private-query-error'} {5} {throw 'Must not retry a failed query.'}
if($observed.status -cne 'unavailable'){throw 'A failed query must be distinguishable from timeout or exit.'}
$errors=@(@($observed.last_in_window,$observed.terminal) | Where-Object {$null -ne $_ -and $_.error_kind -ceq 'query_failed'})
if($errors.Count -ne 1 -or $null -ne $errors[0].marker_present -or $null -ne $errors[0].process_exited){
    throw 'Startup query error was lost or misreported as a known state.'
}
if(($observed | ConvertTo-Json -Depth 10) -like '*synthetic-private*'){throw 'Raw query error leaked.'}
"""
    observed = isolated(tmp_path, ["Wait-FixtureStartup"], expression, {},
                        ["Start-Sleep"], callbacks=("Observe", "ElapsedMilliseconds", "Pause"))
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("kind,phase,role", [
    ("completed", "network_before", "target"),
    ("metadata_unavailable", "network_blocked", "control"),
    ("native_refused", "wdac", "renamed"),
    ("startup_timeout", "network_blocked", "target"),
    ("startup_unavailable", "network_blocked", "control"),
    ("exit_timeout", "network_release", "target"),
    ("exit_before_marker", "hourly_before", "renamed"),
])
def test_fixture_probe_keeps_marker_pid_deadlines_and_outcome_after_failures(tmp_path, kind, phase, role):
    expression = r"""
$work='C:\inert';$result=[ordered]@{fixture_probes=@()};$global:probeSentinel=$null;$global:exitTimeout=$null
function global:Start-Fixture($Path,$Sentinel,$Url,$HoldMilliseconds){
    $global:probeSentinel=$Sentinel
    if($HoldMilliseconds -ne 3000){throw 'Fixture hold time changed.'}
    if($global:catalogTestData.kind -ceq 'native_refused'){
        throw [ComponentModel.Win32Exception]::new(4551,'synthetic-private-native-message')
    }
    $fake=[pscustomobject]@{Id=71;HasExited=($global:catalogTestData.kind -ceq 'exit_before_marker');ExitCode=0}
    $fake|Add-Member ScriptMethod WaitForExit {
        param($Milliseconds)
        $global:exitTimeout=$Milliseconds
        return $global:catalogTestData.kind -cne 'exit_timeout'
    }
    return $fake
}
function global:Wait-FixtureStartup {
    switch($global:catalogTestData.kind){
        'startup_timeout' {return @{status='timeout';elapsed_ms=10101;last_in_window=$null;terminal=@{
            at_ms=10101;marker_present=$true;process_exited=$false;error_kind=$null}}}
        'startup_unavailable' {return @{status='unavailable';elapsed_ms=3;terminal=$null;last_in_window=@{
            at_ms=3;marker_present=$null;process_exited=$null;error_kind='query_failed'}}}
        'exit_before_marker' {return @{status='exited';elapsed_ms=5;terminal=$null;last_in_window=@{
            at_ms=5;marker_present=$false;process_exited=$true;error_kind=$null}}}
        default {return @{status='started';elapsed_ms=5;terminal=$null;last_in_window=@{
            at_ms=5;marker_present=$true;process_exited=$false;error_kind=$null}}}
    }
}
function global:Test-Path {
    if($global:catalogTestData.kind -ceq 'startup_unavailable'){throw 'synthetic-private-query-message'}
    return $global:catalogTestData.kind -notin @('native_refused','startup_timeout')
}
function global:Get-Item {
    if($global:catalogTestData.kind -ceq 'metadata_unavailable'){throw 'synthetic-private-metadata-message'}
    return [pscustomobject]@{CreationTimeUtc=[DateTime]::Parse('2026-11-05T10:10:10Z').ToUniversalTime()}
}
$failed=$false;$failure=$null;$probe=$null
try{$probe=Invoke-Fixture 'C:\inert\fixture.exe' '-' -Phase $fixtureData.phase -Role $fixtureData.role}
catch{$failed=$true;$failure=$_.Exception.Message}
if(@($result.fixture_probes).Count -ne 1){throw 'Each attempted probe must leave one observation even after failure.'}
$row=$result.fixture_probes[0]
if($row.phase -cne $fixtureData.phase -or $row.role -cne $fixtureData.role -or
   $row.sentinel_id -cnotmatch '^[a-f0-9]{32}$' -or
   $row.sentinel_id -cne [IO.Path]::GetFileNameWithoutExtension($global:probeSentinel)){
    throw 'The phase and role cannot be correlated with the unique marker.'
}
$launchStart=[DateTimeOffset]::Parse($row.launch.started_utc)
$launchEnd=[DateTimeOffset]::Parse($row.launch.finished_utc)
if($launchEnd -lt $launchStart -or $null -eq $row.launch.elapsed_ms -or $row.launch.elapsed_ms -lt 0){
    throw 'The launch clock is missing or invalid.'
}
if(($row|ConvertTo-Json -Depth 16) -match 'synthetic-private|C:\\\\inert' -or $failure -like '*synthetic-private*'){
    throw 'Probe evidence exposed a path or raw diagnostic.'
}
if($fixtureData.kind -ceq 'native_refused'){
    if($failed -or $row.status -cne 'native_refused' -or $row.native_error -ne 4551 -or
       $row.process_created -ne $false -or $null -ne $row.pid -or $null -ne $row.startup -or
       $null -ne $row.exit_wait -or $probe.native_error -ne 4551 -or $probe.started -ne $false -or
       $probe.process_created -ne $false){throw 'A native refusal must retain its original code and process state.'}
}else{
    if($row.pid -ne 71 -or $row.process_created -ne $true -or $row.native_error -ne 0){
        throw 'A returned process handle must be associated with its PID.'
    }
    switch($fixtureData.kind){
        'startup_timeout' {
            if(-not $failed -or $row.status -cne 'startup_timeout' -or $row.startup.status -cne 'timeout' -or
               $row.startup.terminal.marker_present -ne $true -or $null -ne $row.exit_wait){
                throw 'A late marker was promoted or its timeout evidence was lost.'
            }
        }
        'startup_unavailable' {
            if(-not $failed -or $row.status -cne 'startup_unavailable' -or
               $row.startup.last_in_window.error_kind -cne 'query_failed' -or $null -ne $row.exit_wait){
                throw 'A failed startup read lost its evidence.'
            }
        }
        'exit_timeout' {
            if(-not $failed -or $row.status -cne 'exit_timeout' -or $row.startup.status -cne 'started' -or
               $row.exit_wait.timed_out -ne $true -or $null -ne $row.exit_wait.exit_code -or
               $null -eq $row.exit_wait.elapsed_ms -or $global:exitTimeout -ne 15000){
                throw 'The distinct exit deadline or its evidence was lost.'
            }
        }
        'exit_before_marker' {
            if($row.startup.status -cne 'exited' -or (-not $failed -and $probe.started -ne $false)){
                throw 'Exit before the marker must never become an observed start.'
            }
        }
        default {
            if($failed -or $row.status -cne 'completed' -or $row.startup.status -cne 'started' -or
               $row.exit_wait.timed_out -ne $false -or $row.exit_wait.exit_code -ne 0 -or
               $null -eq $row.exit_wait.elapsed_ms -or $global:exitTimeout -ne 15000 -or
               $probe.started -ne $true -or $probe.alive_after_sentinel -ne $true -or $probe.exit -ne 0){
                throw 'Successful start and exit must remain separate observations.'
            }
            if($fixtureData.kind -ceq 'metadata_unavailable'){
                if($null -ne $row.marker_created_utc -or $row.marker_metadata_error -cne 'query_failed'){
                    throw 'A diagnostic metadata failure must be explicit without changing acceptance.'
                }
            }elseif($null -eq $row.marker_created_utc -or $null -ne $row.marker_metadata_error){
                throw 'Marker creation UTC was not captured.'
            }
        }
    }
}
"""
    observed = isolated(tmp_path, ["Invoke-Fixture"], expression, {"kind": kind, "phase": phase, "role": role},
                        ["Start-Fixture", "Wait-FixtureStartup", "Wait-Until", "Get-Item", "Test-Path", "Join-Path"],
                        methods=("NewGuid", "StartNew", "Stop", "WaitForExit"))
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("kind", ["complete", "rules_unavailable", "filters_unavailable"])
def test_network_filter_enumeration_has_its_own_clock_and_failure_evidence(tmp_path, kind):
    expression = r"""
$main=@($tree.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Body.Statements.Count -gt 0 -and $node.Body.Statements[0].Extent.Text.TrimStart().StartsWith('Assert-ProductionPackage ')
},$true))
if($main.Count -ne 1){throw 'Expected one acceptance body.'}
$statements=@($main[0].Body.Statements)
$start=@(for($index=0;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text.Contains("Publish-Assignment 'network'")){$index}
})
if($start.Count -ne 1){throw 'Expected one network assignment.'}
$end=@(for($index=$start[0]+1;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text.Contains('Invoke-Fixture')){$index;break}
})
if($end.Count -ne 1 -or $end[0] -le ($start[0]+1)){throw 'Cannot isolate filter enumeration.'}
$selected=@($statements[$start[0]..($end[0]-1)])
$allowed=@('Publish-Assignment','Wait-Ack','Owned-FirewallRules','Get-NetFirewallApplicationFilter',
    'ForEach-Object','Where-Object')
foreach($statement in $selected){
    foreach($command in @($statement.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
        if($command.GetCommandName() -notin $allowed){throw 'Unexpected command in filter enumeration.'}
    }
    foreach($method in @($statement.FindAll({param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true))){
        if($method.Member.Value -notin @('StartNew','Stop','ToString','GetType')){
            throw 'Unexpected method in filter enumeration.'
        }
    }
    if(@($statement.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)).Count){
        throw 'Unexpected function definition in filter enumeration.'
    }
}
$result=[ordered]@{network_enumeration=$null}
$network=@{firewall_paths=@();control_has_rule=$false};$aControl='C:\inert\control.exe'
$global:networkAcked=$false
function Publish-Assignment($Name){if($Name -cne 'network'){throw 'Unexpected policy.'};return @{version=3}}
function Wait-Ack($Assignment){if($Assignment.version -ne 3){throw 'Unexpected ACK.'};$global:networkAcked=$true}
function Owned-FirewallRules {
    if(-not $global:networkAcked){throw 'Filter enumeration preceded the policy ACK.'}
    if($global:catalogTestData.kind -ceq 'rules_unavailable'){throw 'synthetic-private-rules-error'}
    return @([pscustomobject]@{Direction='Inbound'},[pscustomobject]@{Direction='Outbound'})
}
$global:catalogTestData=$fixtureData
function global:Get-NetFirewallApplicationFilter {
    param([Parameter(ValueFromPipeline=$true)]$Rule)
    process{
        if($global:catalogTestData.kind -ceq 'filters_unavailable'){throw 'synthetic-private-filter-error'}
        [pscustomobject]@{Program='C:\inert\fixture.exe'}
    }
}
$failed=$false;$failure=$null
try{. ([scriptblock]::Create(($selected | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine))}
catch{$failed=$true;$failure=$_.Exception.Message}
$row=$result.network_enumeration
if($null -eq $row){throw 'Filter enumeration outcome was lost before the probe started.'}
$started=[DateTimeOffset]::Parse($row.started_utc)
$finished=[DateTimeOffset]::Parse($row.finished_utc)
if($finished -lt $started -or $null -eq $row.elapsed_ms -or $row.elapsed_ms -lt 0){
    throw 'Enumeration must have its own UTC and monotonic clocks.'
}
if(($row | ConvertTo-Json -Depth 8) -like '*synthetic-private*' -or $failure -like '*synthetic-private*'){
    throw 'A raw enumeration error escaped.'
}
if($fixtureData.kind -ceq 'complete'){
    if($failed -or $row.status -cne 'complete' -or $row.rule_count -ne 2 -or $row.filter_count -ne 2 -or
        $null -ne $row.error_kind -or @($network.firewall_paths).Count -ne 2 -or $network.control_has_rule){
        throw 'Enumeration evidence or existing network check was changed.'
    }
}else{
    if(-not $failed -or $row.status -cne 'failed' -or -not $row.error_kind -or $null -ne $row.filter_count){
        throw 'A failed enumeration must keep its own failure outcome and unknown count.'
    }
    if(($fixtureData.kind -ceq 'rules_unavailable' -and $null -ne $row.rule_count) -or
        ($fixtureData.kind -ceq 'filters_unavailable' -and $row.rule_count -ne 2)){
        throw 'Counts captured before the error were lost or invented.'
    }
}
"""
    observed = pure(tmp_path, ["Wait-Ack"], expression, {"kind": kind})
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
def test_all_fixture_probe_calls_identify_their_phase_and_role(tmp_path):
    expression = r"""
$calls=@($tree.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-Fixture'
},$true) | Sort-Object {$_.Extent.StartOffset})
if($calls.Count -ne @($fixtureData.pairs).Count){throw 'The existing fixture probe sequence changed.'}
for($index=0;$index -lt $calls.Count;$index++){
    $actual=@{}
    $elements=@($calls[$index].CommandElements)
    for($offset=1;$offset -lt ($elements.Count-1);$offset++){
        if($elements[$offset] -is [Management.Automation.Language.CommandParameterAst] -and
            $elements[$offset].ParameterName -in @('Phase','Role')){
            $actual[$elements[$offset].ParameterName]=$elements[$offset+1].Value
        }
    }
    if($actual.Phase -cne $fixtureData.pairs[$index].phase -or $actual.Role -cne $fixtureData.pairs[$index].role){
        throw ('Missing or wrong fixture phase/role at probe '+$index+'.')
    }
}
"""
    pairs = [{"phase": phase, "role": role} for phase, roles in [
        ("network_before", ("target", "control")), ("network_blocked", ("target", "control")),
        ("network_release", ("target", "control")), ("wdac", ("original", "renamed")),
        ("hourly_before", ("renamed",)), ("hourly_after", ("renamed",)), ("release", ("original", "renamed")),
    ] for role in roles]
    observed = pure(tmp_path, ["Wait-Ack"], expression, {"pairs": pairs})
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("change", [
    "missing_firewall", "baseline_replaced", "query_failed", "truncated", "boolean_rule_count",
    "removed_rule", "changed_enabled", "duplicate_after", "fabricated_difference", "partial_cleanup",
    "missing_acks", "foreign_ack_identity", "downgrade",
])
def test_v2_guest_rejects_unobserved_firewall_and_cleanup_despite_passed_flags(tmp_path, change):
    manifest = direct_v2_manifest()
    report = v2_mutation(report_for(manifest), change)
    observed = pure(tmp_path, ["Assert-DeniedExecution", "Assert-HourlyEvidence", "Assert-CatalogEvidence"],
                    "Assert-CatalogEvidence $fixtureData.report $fixtureData.manifest",
                    {"report": report, "manifest": manifest})
    assert observed["accepted"] is False, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("kind", ["empty", "owned_filtered", "failed", "truncated"])
def test_firewall_snapshot_records_completeness_and_never_coerces_query_failure_to_empty(tmp_path, kind):
    native = [{"Name": "rule-" + str(index), "Enabled": "True", "Direction": "Inbound", "Action": "Allow", "Group": ""}
              for index in range(3 if kind == "truncated" else 1)]
    if kind == "empty":
        native = []
    elif kind == "owned_filtered":
        native.append({"Name": "own-rule", "Enabled": "False", "Direction": "Outbound",
                       "Action": "Block", "Group": "openems application control"})
    expression = r"""
$applicationGroup='openems application control'
function global:Get-NetFirewallRule {
    if($global:catalogTestData.kind -ceq 'failed'){throw 'synthetic-sensitive-diagnostic'}
    return @($global:catalogTestData.native)
}
$snapshot=Capture-FirewallSnapshot 2
if($fixtureData.kind -ceq 'failed'){
    if($snapshot.status -cne 'failed' -or -not $snapshot.error -or $snapshot.error -like '*sensitive*'){
        throw 'A failed query must be explicit and sanitized.'
    }
}elseif($fixtureData.kind -ceq 'truncated'){
    if($snapshot.status -cne 'truncated' -or $snapshot.truncated -ne $true -or
        $snapshot.observed_count -ne 3 -or @($snapshot.rules).Count -ne 2){throw 'Truncation was hidden.'}
}else{
    if($snapshot.status -cne 'complete' -or $snapshot.truncated -ne $false -or $null -ne $snapshot.error -or
        $snapshot.observed_count -ne $fixtureData.expected){throw 'Snapshot completeness changed.'}
    if(@($snapshot.rules).Count -ne $fixtureData.expected){throw 'Owned rule or empty-query handling changed.'}
    if($fixtureData.expected -gt 0 -and ($snapshot.rules[0].enabled -cne 'True' -or
        $snapshot.rules[0].direction -cne 'Inbound' -or $snapshot.rules[0].action -cne 'Allow')){
        throw 'CIM enum values did not retain canonical scalar meaning.'
    }
}
$null=[DateTimeOffset]::Parse($snapshot.at_utc)
"""
    observed = isolated(tmp_path, ["Capture-FirewallSnapshot"], expression,
                        {"kind": kind, "native": native, "expected": 0 if kind == "empty" else 1},
                        ["Get-NetFirewallRule"])
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("error,expected", [
    ("enforcement failed: OSError", "OSError"),
    ("enforcement failed: LocalError", "LocalError"),
    (None, "unknown"),
    ("enforcement failed: token=synthetic-sensitive-marker", "unknown"),
])
def test_negative_ack_retains_safe_category_and_exact_identity_without_raw_text(tmp_path, error, expected):
    assignment = {"version": 6, "digest": "c" * 64}
    expression = r"""
$manifest=$fixtureData.manifest
$row=Ack-Observation $fixtureData.upload '2026-11-02T16:00:00Z'
if($row.version -ne 6 -or $row.digest -cne $fixtureData.upload.digest -or $row.success -ne $false -or
    $row.at_utc -cne '2026-11-02T16:00:00Z' -or $row.error_kind -cne $fixtureData.expected){
    throw 'ACK identity, failure or safe category was lost.'
}
$serialized=$row|ConvertTo-Json -Compress
if($serialized -like '*synthetic-sensitive-marker*' -or @($row.Keys).Count -ne 5){
    throw 'An ACK leaked raw diagnostic fields.'
}
"""
    observed = isolated(tmp_path, ["Ack-Observation"], expression, {
        "manifest": direct_v2_manifest(),
        "upload": {**assignment, "success": False, "error": error}, "expected": expected,
    })
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("firewall_changed,query_failed", [(True, False), (False, True)])
def test_cleanup_collects_other_fields_even_when_firewall_or_service_query_fails(tmp_path, firewall_changed, query_failed):
    before = firewall_snapshot()
    after = firewall_snapshot(at_utc="2026-11-02T17:01:00Z")
    if firewall_changed:
        after["rules"][0]["enabled"] = "False"
    expression = r"""
function global:Capture-FirewallSnapshot {return $global:catalogTestData.after}
function global:Get-Service {if($global:catalogTestData.query_failed){throw 'synthetic-sensitive-diagnostic'};return $null}
function global:Get-ScheduledTask {return @()}
function global:Get-DnsClientNrptRule {return @()}
function global:Owned-FirewallRules {return @()}
function global:Own-Policy {return $null}
function global:Foreign-PolicyIds {return @('foreign-policy')}
function global:Test-Path {return $false}
$cleanup=Collect-CleanupEvidence $fixtureData.before 0 @('foreign-policy') @()
if($cleanup.msi_exit -ne 0 -or $cleanup.watchdog_present -ne $false -or $cleanup.nrpt_count -ne 0 -or
    $cleanup.owned_firewall_rules -ne 0 -or $cleanup.own_policy_present -ne $false -or
    $cleanup.fixture_registry_present -ne $false -or @($cleanup.foreign_after).Count -ne 1){
    throw 'A failed check suppressed independent cleanup observations.'
}
if($fixtureData.query_failed){
    if($cleanup.collection_status -cne 'partial' -or $null -ne $cleanup.service_present -or
        @($cleanup.collection_errors | Where-Object field -EQ 'service_present').Count -ne 1){
        throw 'A failed query masqueraded as an absent service.'
    }
    if(($cleanup|ConvertTo-Json -Depth 12) -like '*sensitive*'){throw 'Raw cleanup error leaked.'}
}else{
    if($cleanup.collection_status -cne 'complete' -or @($cleanup.collection_errors).Count -ne 0 -or
        $cleanup.firewall.preserved -ne $false -or @($cleanup.firewall.differences).Count -ne 1){
        throw 'Firewall drift disappeared or prevented complete cleanup evidence.'
    }
}
"""
    observed = isolated(tmp_path, ["Compare-FirewallSnapshots", "Collect-CleanupEvidence"], expression,
                        {"before": before, "after": after, "query_failed": query_failed},
                        ["Capture-FirewallSnapshot", "Get-Service", "Get-ScheduledTask", "Get-DnsClientNrptRule",
                         "Owned-FirewallRules", "Own-Policy", "Foreign-PolicyIds", "Test-Path"])
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
def test_firewall_baseline_is_in_the_persisted_report_before_the_first_msi(tmp_path):
    expression = r"""
$main=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Body.Statements.Count -gt 0 -and $node.Body.Statements[0].Extent.Text.TrimStart().StartsWith('Assert-ProductionPackage ')
},$true))
if($main.Count -ne 1){throw 'Expected one actual acceptance body.'}
$statements=@($main[0].Body.Statements)
$start=@(for($index=0;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text -match '^\$firewallBefore\s*='){$index}
})
$end=@(for($index=0;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text.Contains('Invoke-Msi $false')){$index}
})
if($start.Count -ne 1 -or $end.Count -ne 1){throw 'Cannot isolate baseline-to-install stage.'}
$selected=@($statements[$start[0]..$end[0]])
$allowed=@('Firewall-Snapshot','Capture-FirewallSnapshot','Owned-FirewallRules','Join-Path','Get-Sha256',
    'Publish-Assignment','Start-Backend','Invoke-Msi','Write-Report','Field')
foreach($statement in $selected){
    foreach($command in @($statement.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
        if($command.GetCommandName() -notin $allowed){throw 'Unexpected baseline-stage command.'}
    }
    if(@($statement.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count){
        throw 'Unexpected baseline-stage method.'
    }
}
$manifest=$fixtureData.manifest;$work='C:\inert';$resultPath='C:\inert\result.json'
$result=@{status='running';firewall_before=$null};$script:persistedBaseline=$null;$script:msiCalls=0
function Firewall-Snapshot {return @()}
function Capture-FirewallSnapshot {return $fixtureData.before}
function Owned-FirewallRules {return @()}
function Get-Sha256 {return 'synthetic-hosts-hash'}
function Publish-Assignment {return $manifest.policies.allow}
function Start-Backend {return [pscustomobject]@{State='Running'}}
function Write-Report($Path,$Value){$script:persistedBaseline=$Value.firewall_before}
function Invoke-Msi([bool]$Remove){
    if($Remove){throw 'Unexpected removal.'}
    $script:msiCalls++
    if($null -eq $script:persistedBaseline -or $script:persistedBaseline.status -cne 'complete' -or
        $script:persistedBaseline.rules[0].name -cne 'foreign-rule'){throw 'MSI started before baseline persistence.'}
    return 0
}
. ([scriptblock]::Create(($selected | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine))
if($script:msiCalls -ne 1){throw 'Isolated installation boundary was not reached.'}
"""
    observed = pure(tmp_path, ["Wait-Ack"], expression,
                    {"manifest": direct_v2_manifest(), "before": firewall_snapshot()})
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("firewall_changed", [False, True])
def test_catch_finally_keeps_cleanup_and_only_publishes_final_failure_after_finished_timestamp(tmp_path, firewall_changed):
    manifest = direct_v2_manifest()
    cleanup = report_for(manifest)["checks"][-1]["evidence"]
    if firewall_changed:
        cleanup["firewall"]["after"]["rules"][0]["enabled"] = "False"
        cleanup["firewall"]["differences"] = [{"name": "foreign-rule", "kind": "changed", "fields": ["enabled"]}]
        cleanup["firewall"]["preserved"] = False
    expression = r"""
$main=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Body.Statements.Count -gt 0 -and $node.Body.Statements[0].Extent.Text.TrimStart().StartsWith('Assert-ProductionPackage ')
},$true))
if($main.Count -ne 1 -or $main[0].CatchClauses.Count -ne 1 -or $null -eq $main[0].Finally){throw 'Expected actual catch/finally.'}
$selected=@($main[0].CatchClauses[0],$main[0].Finally)
$allowed=@('Get-Service','Publish-Assignment','Wait-Ack','Invoke-Msi','Test-Path','Remove-Item','Stop-Job','Remove-Job',
    'Owned-FirewallRules','Assert-FirewallPreserved','Get-Sha256','Get-ScheduledTask','Where-Object',
    'Get-DnsClientNrptRule','Own-Policy','Foreign-PolicyIds','Record-Check','Assert-CatalogEvidence',
    'Write-Report','Collect-CleanupEvidence','Read-Rows','Field')
foreach($part in $selected){
    foreach($command in @($part.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
        if($command.GetCommandName() -notin $allowed){throw 'Unexpected command in isolated finalization.'}
    }
}
$result=[ordered]@{status='running';passed=$false;error=$null;cleanup_errors=@();checks=@();finished_utc=$null}
$ownedProcesses=@();$registryPaths=@();$backend=$null;$installed=$false;$msiRemovalExit=0
$codeBefore=@('foreign-policy');$hostsBefore=$null;$resultPath='C:\inert\result.json'
$firewallBefore=$fixtureData.cleanup.firewall.before;$manifest=$fixtureData.manifest
$script:publications=@()
function global:Get-Service {return $null}
function global:Get-ScheduledTask {return @()}
function global:Get-DnsClientNrptRule {return @()}
function Owned-FirewallRules {return @()}
function Own-Policy {return $null}
function Foreign-PolicyIds {return @('foreign-policy')}
function Assert-FirewallPreserved {if($fixtureData.firewall_changed){throw 'Synthetic foreign firewall drift.'}}
function Collect-CleanupEvidence {return $fixtureData.cleanup}
function Stop-Job {throw 'A real job must never be stopped by this test.'}
function Remove-Job {throw 'A real job must never be removed by this test.'}
function Write-Report($Path,$Value){
    $script:publications+=@(($Value|ConvertTo-Json -Depth 24|ConvertFrom-Json))
}
function Record-Check($Name,$Evidence){
    $result.checks+=@(@{name=$Name;evidence=$Evidence;status='passed'})
    Write-Report $resultPath $result
}
$program='try { throw ''Synthetic original failure.'' } '+$main[0].CatchClauses[0].Extent.Text+
    ' finally '+$main[0].Finally.Extent.Text
. ([scriptblock]::Create($program))
if(@($result.checks|Where-Object name -EQ 'cleanup').Count -ne 1){throw 'Failure suppressed cleanup evidence.'}
if($result.status -cne 'failed' -or -not $result.finished_utc){throw 'Original failure lost its final status.'}
foreach($published in $script:publications){
    if($published.status -cne 'running' -and -not $published.finished_utc){
        throw 'Parent could observe a final status before cleanup completed.'
    }
}
"""
    observed = pure(tmp_path, ["Wait-Ack"], expression,
                    {"manifest": manifest, "cleanup": cleanup, "firewall_changed": firewall_changed, "rows": []})
    assert observed["accepted"] is True, observed


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
