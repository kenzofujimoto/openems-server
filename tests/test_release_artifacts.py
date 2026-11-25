"""A public release must promote the exact production bytes accepted in the lab."""

from __future__ import annotations

import hashlib
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def artifact_tools():
    specification = importlib.util.spec_from_file_location("release_artifacts", ROOT / "tools/release_artifacts.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def fixture_packages(tmp_path):
    for name in ("openems-agent.msi", "openems-agent-next.msi", "openems-agent.exe", "openems-session.exe"):
        (tmp_path / name).write_bytes(("inert test bytes for " + name).encode())
    agent_hash = hashlib.sha256((tmp_path / "openems-agent.exe").read_bytes()).hexdigest()

    def inspect(path):
        return {
            "product_version": "1.0.1" if path.name.endswith("-next.msi") else "1.0.0",
            "upgrade_code": "0C684B18-7540-4865-9516-567A9E81AA61",
            "custom_actions": ["PrepareAgentSetup", "PrepareAgentRemoval"],
            "properties": ["SERVER", "INVITATION"],
            "agent_actions_sha256": agent_hash,
            "signature_status": "NotSigned",
        }

    return inspect


def freeze(tmp_path, inspect=None):
    default_inspect = fixture_packages(tmp_path)
    tool = artifact_tools()
    manifest = tool.freeze_candidate(tmp_path, "a" * 40, "1.0.0", inspect or default_inspect)
    path = tmp_path / "candidate-manifest.json"
    assert path.is_file()
    return tool, manifest, hashlib.sha256(path.read_bytes()).hexdigest()


def native_reports(tool, manifest):
    return {phase: {"passed": True, "cleanup_errors": [], "package_receipt": {
        "source_revision": manifest["source_revision"], "packages": manifest["packages"],
    }} for phase in tool.REQUIRED_ACCEPTANCES}


def server_fixture(tmp_path, manifest):
    directory = tmp_path / "server"
    directory.mkdir()
    archive = "openems-server-1.0.0-linux-amd64.tar.gz"
    payload = b"inert frozen server image archive bytes"
    (directory / archive).write_bytes(payload)
    server = {
        "schema_version": 1, "version": manifest["version"], "source_revision": manifest["source_revision"],
        "status": "image_built_runtime_acceptance_pending", "local_tag": "openems-server:v1.0.0-rc1-fixture",
        "image_id": "sha256:" + "b" * 64, "platform": "linux/amd64", "file": archive,
        "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload),
        "inspection": {"version": "1.0.0", "panel_present": True, "migration_008_present": True},
    }
    path = directory / "server-image-manifest.json"
    path.write_text(json.dumps(server), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = {name: server[name] for name in ("source_revision", "version", "image_id", "platform", "file", "sha256", "bytes")}
    receipt["manifest_sha256"] = digest
    report = {
        "schema_version": 1, "passed": True, "cleanup_errors": [], "server_receipt": copy.deepcopy(receipt),
        "independent_review": {"passed": True, "reviewer": "independent-reviewer", "evidence_sha256": "c" * 64},
        "scan": {
            "passed": True, "policy": "no-fixable-high-or-critical", "fixable_high": 0, "fixable_critical": 0,
            "unfixed_findings_reported": 222, "evidence_sha256": "d" * 64, "server_receipt": copy.deepcopy(receipt),
        },
        "acceptance": {
            "api": {
                "passed": True, "real_runtime": True, "evidence_sha256": "e" * 64,
                "server_receipt": copy.deepcopy(receipt),
                "checks": {"health_version": True, "migrations": True, "authenticated_policy_publication": True},
            },
            "panel": {
                "passed": True, "real_runtime": True, "evidence_sha256": "f" * 64,
                "server_receipt": copy.deepcopy(receipt),
                "checks": {"login": True, "csrf": True, "policy_publication": True, "reload_persistence": True},
            },
        },
    }
    return server, {
        "server_directory": directory, "server_manifest_sha256": digest, "server_report": report,
    }


def test_freeze_records_installer_payload_and_unsigned_distribution(tmp_path):
    tool, manifest, digest = freeze(tmp_path)
    assert manifest["version"] == "1.0.0"
    assert manifest["source_revision"] == "a" * 40
    assert manifest["distribution_signature"] == "unsigned"
    assert manifest["upgrade_fixture_version"] == "1.0.1"
    assert set(manifest["packages"]) == {"openems-agent.msi", "openems-agent-next.msi"}
    assert tool.read_candidate(tmp_path, digest, "1.0.0") == manifest


@pytest.mark.parametrize("name", ["openems-agent.msi", "openems-agent-next.msi", "openems-agent.exe", "openems-session.exe"])
def test_a_changed_package_or_payload_is_refused(tmp_path, name):
    tool, _, digest = freeze(tmp_path)
    (tmp_path / name).write_bytes(b"changed after acceptance")
    with pytest.raises(ValueError, match=r"changed|mismatch"):
        tool.read_candidate(tmp_path, digest, "1.0.0")


def test_a_changed_manifest_cannot_redefine_the_accepted_files(tmp_path):
    tool, manifest, digest = freeze(tmp_path)
    manifest["source_revision"] = "b" * 40
    (tmp_path / "candidate-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"):
        tool.read_candidate(tmp_path, digest, "1.0.0")


def test_freezing_again_cannot_overwrite_an_existing_candidate(tmp_path):
    tool, _, _ = freeze(tmp_path)
    before = (tmp_path / "candidate-manifest.json").read_bytes()
    with pytest.raises(ValueError, match=r"already|exists"):
        tool.freeze_candidate(tmp_path, "b" * 40, "1.0.0", fixture_packages(tmp_path))
    assert (tmp_path / "candidate-manifest.json").read_bytes() == before


@pytest.mark.parametrize("version", ["1.0.0-rc.1", "256.0.0", "1.0.65535", "1.00.0"])
def test_an_unrepresentable_or_ambiguous_msi_pair_is_refused(tmp_path, version):
    inspect = fixture_packages(tmp_path)
    with pytest.raises(ValueError, match="version"):
        artifact_tools().freeze_candidate(tmp_path, "a" * 40, version, inspect)
    assert not (tmp_path / "candidate-manifest.json").exists()


@pytest.mark.parametrize("kind", ["injected_action", "injected_property", "wrong_version", "wrong_upgrade", "wrong_payload", "unverified_signature"])
def test_freeze_refuses_fixtures_and_mismatched_installer_identity(tmp_path, kind):
    base_inspect = fixture_packages(tmp_path)

    def inspect(path):
        value = base_inspect(path)
        if kind == "injected_action":
            value["custom_actions"].append("InjectSetupFailure")
        elif kind == "injected_property":
            value["properties"].append("FAIL_REMOVAL")
        elif kind == "wrong_version":
            value["product_version"] = "0.4.0"
        elif kind == "wrong_upgrade":
            value["upgrade_code"] = "different-product"
        elif kind == "wrong_payload":
            value["agent_actions_sha256"] = "0" * 64
        else:
            value["signature_status"] = "UnknownError"
        return value

    with pytest.raises(ValueError):
        artifact_tools().freeze_candidate(tmp_path, "a" * 40, "1.0.0", inspect)
    assert not (tmp_path / "candidate-manifest.json").exists()


def test_release_assets_exclude_upgrade_fixture_and_require_every_acceptance(tmp_path):
    tool, manifest, _ = freeze(tmp_path)
    reports = {
        phase: {"passed": True, "cleanup_errors": [], "package_receipt": {
            "source_revision": manifest["source_revision"], "packages": manifest["packages"],
        }} for phase in tool.REQUIRED_ACCEPTANCES
    }
    assert "pilot" in reports and "antibypass" in reports and "ordered-domains" in reports
    server, gate = server_fixture(tmp_path, manifest)
    assets = tool.release_asset_names(manifest, reports, **gate)
    assert "openems-agent.msi" in assets
    assert "openems-agent-next.msi" not in assets
    assert not any("0.2." in name for name in assets)
    assert set(assets) == {"openems-agent.msi", "candidate-manifest.json", server["file"], "server-image-manifest.json", "SHA256SUMS"}
    reports.pop("pilot")
    with pytest.raises(ValueError, match="pilot"):
        tool.release_asset_names(manifest, reports, **gate)


@pytest.mark.parametrize("failure", ["wrong_package", "wrong_source", "cleanup", "not_passed"])
def test_an_acceptance_flag_does_not_override_stale_bytes_or_cleanup_errors(tmp_path, failure):
    tool, manifest, _ = freeze(tmp_path)
    reports = {phase: {"passed": True, "cleanup_errors": [], "package_receipt": {
        "source_revision": manifest["source_revision"], "packages": manifest["packages"],
    }} for phase in tool.REQUIRED_ACCEPTANCES}
    report = reports["browser-trust"]
    if failure == "wrong_package":
        report["package_receipt"]["packages"] = {}
    elif failure == "wrong_source":
        report["package_receipt"]["source_revision"] = "b" * 40
    elif failure == "cleanup":
        report["cleanup_errors"] = ["managed root remained"]
    else:
        report["passed"] = False
    with pytest.raises(ValueError, match="browser-trust"):
        tool.release_asset_names(manifest, reports)


def test_msi_acceptances_alone_can_never_authorize_release(tmp_path):
    tool, manifest, _ = freeze(tmp_path)
    with pytest.raises(ValueError, match=r"[Ss]erver"):
        tool.release_asset_names(manifest, native_reports(tool, manifest))


@pytest.mark.parametrize("missing", ["server_directory", "server_manifest_sha256", "server_report"])
def test_server_promotion_requires_the_complete_pinned_gate(tmp_path, missing):
    tool, manifest, _ = freeze(tmp_path)
    _, gate = server_fixture(tmp_path, manifest)
    gate.pop(missing)
    with pytest.raises(ValueError, match=r"[Ss]erver"):
        tool.release_asset_names(manifest, native_reports(tool, manifest), **gate)


def test_read_server_candidate_verifies_the_real_manifest_shape_and_archive(tmp_path):
    tool, manifest, _ = freeze(tmp_path)
    server, gate = server_fixture(tmp_path, manifest)
    before = {path.name: path.read_bytes() for path in gate["server_directory"].iterdir()}
    assert tool.read_server_candidate(gate["server_directory"], gate["server_manifest_sha256"], "1.0.0", "a" * 40) == server
    assert {path.name: path.read_bytes() for path in gate["server_directory"].iterdir()} == before


@pytest.mark.parametrize("failure", ["version", "source", "image_id", "archive_name", "platform", "inspection", "boolean_size", "manifest_hash", "archive_changed"])
def test_server_candidate_refuses_stale_or_ambiguous_image_identity(tmp_path, failure):
    tool, manifest, _ = freeze(tmp_path)
    server, gate = server_fixture(tmp_path, manifest)
    if failure == "version":
        server["version"] = "0.4.0"
    elif failure == "source":
        server["source_revision"] = "b" * 40
    elif failure == "image_id":
        server["image_id"] = "openems-server:mutable-tag"
    elif failure == "archive_name":
        server["file"] = "../outside.tar.gz"
    elif failure == "platform":
        server["platform"] = "linux/arm64"
    elif failure == "inspection":
        server["inspection"]["panel_present"] = False
    elif failure == "boolean_size":
        server["bytes"] = True
    elif failure == "archive_changed":
        (gate["server_directory"] / server["file"]).write_bytes(b"not the frozen image")
    path = gate["server_directory"] / "server-image-manifest.json"
    path.write_text(json.dumps(server), encoding="utf-8")
    digest = "0" * 64 if failure == "manifest_hash" else hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match=r"[Ss]erver"):
        tool.read_server_candidate(gate["server_directory"], digest, "1.0.0", "a" * 40)


def test_server_archive_can_exceed_the_native_package_limit_and_is_streamed(tmp_path, monkeypatch):
    tool, manifest, _ = freeze(tmp_path)
    server, gate = server_fixture(tmp_path, manifest)
    archive = gate["server_directory"] / server["file"]
    with archive.open("r+b") as stream:
        stream.truncate(tool.MAX_ARTIFACT_BYTES + 1)
    with archive.open("rb") as stream:
        server["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    server["bytes"] = archive.stat().st_size
    path = gate["server_directory"] / "server-image-manifest.json"
    path.write_text(json.dumps(server), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    def no_whole_archive_read(path):
        pytest.fail("Large archives must be hashed by streaming, not Path.read_bytes().")

    monkeypatch.setattr(Path, "read_bytes", no_whole_archive_read)
    assert tool.read_server_candidate(gate["server_directory"], digest, "1.0.0", "a" * 40) == server


@pytest.mark.parametrize(("field", "value"), [
    pytest.param("server_receipt.image_id", "sha256:" + "0" * 64, id="wrong_image"),
    pytest.param("server_receipt.sha256", "0" * 64, id="wrong_archive"),
    pytest.param("server_receipt.source_revision", "b" * 40, id="wrong_source"),
    pytest.param("server_receipt.version", "0.4.0", id="wrong_version"),
    pytest.param("server_receipt.manifest_sha256", "0" * 64, id="wrong_manifest"),
    pytest.param("independent_review.passed", False, id="not_reviewed"),
    pytest.param("independent_review.evidence_sha256", None, id="missing_review_evidence"),
    pytest.param("independent_review.status", "failed", id="failed_review_status"),
    pytest.param("independent_review.status", {}, id="malformed_review_status"),
    pytest.param("independent_review.cleanup_errors", ["review evidence remained"], id="failed_review_cleanup"),
    pytest.param("cleanup_errors", ["database cleanup failed"], id="cleanup"),
    pytest.param("passed", False, id="not_passed"),
    pytest.param("status", {}, id="malformed_status"),
    pytest.param("scan.policy", "ignore-all", id="wrong_policy"),
    pytest.param("scan.fixable_high", 1, id="fixable_high"),
    pytest.param("scan.fixable_critical", 1, id="fixable_critical"),
    pytest.param("scan.fixable_high", False, id="boolean_fixable_count"),
    pytest.param("scan.unfixed_findings_reported", None, id="missing_unfixed_count"),
    pytest.param("scan.unfixed_findings_reported", -1, id="negative_unfixed_count"),
    pytest.param("scan.server_receipt.image_id", "sha256:" + "0" * 64, id="stale_scan"),
    pytest.param("scan.evidence_sha256", None, id="missing_scan_evidence"),
    pytest.param("scan.status", "pending", id="pending_scan"),
    pytest.param("scan.status", [], id="malformed_scan_status"),
    pytest.param("scan.cleanup_errors", ["scan did not finish"], id="failed_scan_cleanup"),
    pytest.param("acceptance.api.real_runtime", False, id="contract_only_api"),
    pytest.param("acceptance.api.passed", False, id="failed_api"),
    pytest.param("acceptance.api.status", "running", id="running_api"),
    pytest.param("acceptance.api.status", {}, id="malformed_api_status"),
    pytest.param("acceptance.api.checks.migrations", None, id="missing_api_migration"),
    pytest.param("acceptance.panel.checks.csrf", None, id="missing_panel_csrf"),
    pytest.param("acceptance.panel.checks.reload_persistence", False, id="failed_panel_reload"),
    pytest.param("acceptance.panel.server_receipt.image_id", "sha256:" + "0" * 64, id="stale_panel"),
    pytest.param("acceptance.panel.cleanup_errors", ["panel data remained"], id="failed_panel_cleanup"),
])
def test_server_flags_cannot_override_missing_runtime_scan_or_independent_evidence(tmp_path, field, value):
    tool, manifest, _ = freeze(tmp_path)
    _, gate = server_fixture(tmp_path, manifest)
    report = gate["server_report"]
    keys = field.split(".")
    for key in keys[:-1]:
        report = report[key]
    if value is None:
        report.pop(keys[-1])
    else:
        report[keys[-1]] = value
    with pytest.raises(ValueError, match=r"[Ss]erver"):
        tool.release_asset_names(manifest, native_reports(tool, manifest), **gate)


def test_final_acceptance_can_plan_existing_artifacts_without_building(tmp_path):
    result = subprocess.run([
        sys.executable, str(ROOT / "tools/build_final_acceptance.py"), "--plan",
        "--packages-from", str(tmp_path), "--manifest-sha256", "b" * 64,
    ], capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["fresh_build"] is False
    assert json.loads(result.stdout)["launches_sandbox"] is False


@pytest.mark.parametrize("missing", ["--manifest-sha256", "--packages-from"])
def test_prebuilt_selection_requires_both_directory_and_pinned_identity(tmp_path, missing):
    arguments = {"--packages-from": str(tmp_path), "--manifest-sha256": "b" * 64}
    arguments.pop(missing)
    command = [sys.executable, str(ROOT / "tools/build_final_acceptance.py"), "--plan"]
    for key, value in arguments.items():
        command.extend((key, value))
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode != 0


def test_prebuilt_staging_copies_verified_bytes_and_never_runs_cargo_or_wix(tmp_path, monkeypatch):
    import build_final_acceptance as builder

    source = tmp_path / "frozen"
    source.mkdir()
    _, manifest, digest = freeze(source)
    output = tmp_path / "staged"
    calls = []

    def only_copy_harnesses(arguments, **kwargs):
        calls.append(arguments)
        assert arguments[0] == sys.executable
        assert Path(arguments[1]).name in {
            "build_session_sandbox.py", "build_locations_sandbox.py", "build_controls_sandbox.py",
        }
        subprocess.run(arguments, cwd=ROOT, check=True, timeout=30)

    def must_not_rebuild():
        pytest.fail("A frozen package must not depend on or rebuild the current native checkout.")

    monkeypatch.setattr(builder, "checked", only_copy_harnesses)
    monkeypatch.setattr(builder, "require_committed_native_sources", must_not_rebuild)
    monkeypatch.setattr(builder, "revision", must_not_rebuild)
    monkeypatch.setattr(sys, "argv", [
        "build_final_acceptance.py", "--output", str(output), "--packages-from", str(source),
        "--manifest-sha256", digest,
    ])
    assert builder.main() == 0
    staged = json.loads((output / "acceptance-manifest.json").read_text(encoding="utf-8"))
    assert staged["source_revision"] == manifest["source_revision"]
    assert staged["packages"] == manifest["packages"]
    assert len(calls) == 4
    for phase in builder.PHASES:
        for package in manifest["packages"]:
            assert (output / (phase + "-input") / package).read_bytes() == (source / package).read_bytes()


def test_staging_cannot_overwrite_an_existing_acceptance_directory(tmp_path, monkeypatch):
    import build_final_acceptance as builder

    source = tmp_path / "frozen"
    source.mkdir()
    _, _, digest = freeze(source)
    output = tmp_path / "previous-results"
    output.mkdir()
    (output / "preserved.json").write_bytes(b"original evidence")
    monkeypatch.setattr(sys, "argv", [
        "build_final_acceptance.py", "--output", str(output), "--packages-from", str(source),
        "--manifest-sha256", digest,
    ])
    with pytest.raises(RuntimeError, match=r"new|empty|exists"):
        builder.main()
    assert (output / "preserved.json").read_bytes() == b"original evidence"
