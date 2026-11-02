#!/usr/bin/env python3
"""Prepare and verify a receipt-bound, disposable-VM catalog acceptance package.

Fixtures are compiled but never executed on this host. Policies are published
through the real in-process server API using explicitly synthetic inventory.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PACKAGES = ("openems-agent.msi", "openems-agent-next.msi")
CASES = ("allow", "absent", "network", "network_release", "present", "later", "release")
CHECKS = ("absent", "network", "process", "wdac", "all_absent", "hourly", "release", "cleanup")
HARNESS = ROOT / "deploy/test-catalog-sandbox.ps1"
DENIAL_CODES = {577, 1260, 4551}


def revision() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def file_record(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _json(path: Path) -> dict[str, Any]:
    return _object(json.loads(path.read_text(encoding="utf-8-sig")), path.name)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _safe_name(name: Any) -> str:
    if not isinstance(name, str) or not name or name in {".", ".."} or any(char in name for char in "/\\:"):
        raise ValueError("package files must have plain filenames")
    return name


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("run_id must be a lowercase UUID hex string")
    return value


def _revision(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("source_revision must be a complete Git revision")
    return value


def _verify_file(path: Path, expected: Any) -> None:
    expected = _object(expected, "file record")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or linked package file: {path.name}")
    if type(expected.get("bytes")) is not int or expected["bytes"] < 1:
        raise ValueError(f"invalid file size: {path.name}")
    if expected != file_record(path):
        raise ValueError(f"package file changed: {path.name}")


def _source_receipt(source: Path) -> tuple[str, dict[str, Any]]:
    receipt = _json(source / "acceptance-manifest.json")
    current = _revision(revision())
    if receipt.get("source_revision") != current:
        raise ValueError("MSI source revision does not match the current committed revision")
    packages = _object(receipt.get("packages"), "packages")
    if set(packages) != set(PACKAGES):
        raise ValueError("the current production and upgrade MSI pair is required")
    for name in PACKAGES:
        _verify_file(source / "final-msi" / name, packages[name])
    return current, packages


def compile_fixture(path: Path, type_name: str) -> None:
    """Compile a small .NET Framework PE; deliberately never start the output."""
    if os.name != "nt" or re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", type_name) is None:
        raise ValueError("fixture compilation requires Windows and a valid type name")
    compiler = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        raise RuntimeError("the Windows .NET Framework C# compiler is required")
    source = path.with_suffix(".cs")
    code = r'''using System;
using System.IO;
using System.Net;
using System.Threading;
public static class TYPE_NAME {
    public static int Main(string[] args) {
        if (args.Length < 1) return 64;
        int result = 0;
        try {
            File.WriteAllText(args[0], "started");
            if (args.Length > 1 && args[1] != "-") {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                var request = WebRequest.Create(args[1]);
                request.Timeout = 8000;
                using (var response = request.GetResponse()) { }
            }
        } catch (Exception error) {
            Console.Error.WriteLine(error.GetType().Name);
            result = 42;
        }
        if (args.Length > 2) Thread.Sleep(Int32.Parse(args[2]));
        return result;
    }
}
'''.replace("TYPE_NAME", type_name)
    source.write_text(code, encoding="utf-8-sig")
    try:
        subprocess.run([str(compiler), "/nologo", "/target:exe", "/platform:x64",
                        "/out:" + str(path), str(source)], check=True, capture_output=True, text=True, timeout=90)
    finally:
        source.unlink(missing_ok=True)
    if not path.is_file() or path.read_bytes()[:2] != b"MZ":
        raise RuntimeError("fixture compiler did not produce a Windows executable")


def _fixtures(output: Path, run_id: str) -> dict[str, Any]:
    fixtures = {}
    for key in ("a", "b"):
        filename = f"openems-catalog-{key}.exe"
        renamed = f"openems-catalog-{key}-renamed.exe"
        compile_fixture(output / filename, f"OpenemsCatalogFixture{key.upper()}{run_id}")
        shutil.copyfile(output / filename, output / renamed)
        fixtures[key] = {"file": filename, "renamed_file": renamed,
                         "sha256": file_record(output / filename)["sha256"],
                         "installed_name": f"OpenEMS Acceptance Fixture {key.upper()}",
                         "app_id": f"OpenEMS.Acceptance{key.upper()}"}
    if fixtures["a"]["sha256"] == fixtures["b"]["sha256"]:
        raise ValueError("the present and later fixtures must have different identities")
    return fixtures


def _synthetic_catalog(fixtures: dict[str, Any], now: datetime) -> dict[str, Any]:
    from app.app_catalog import normalize_name

    return {"version": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "synthetic_fixture": True,
            "source": "openems-owned-acceptance-fixtures", "attribution": "OpenEMS synthetic acceptance fixtures; not winget data.",
            "categories": [{"id": "games", "label": "Synthetic acceptance fixtures", "apps": 2}],
            "apps": [{"id": item["app_id"], "name": item["installed_name"], "vendor": "openemsacceptance",
                      "category": "games", "names": [normalize_name(item["installed_name"])],
                      "commands": [Path(item["file"]).stem], "product_codes": [], "blockable": True}
                     for item in fixtures.values()]}


def _successful(response: Any) -> dict[str, Any]:
    if response.status_code != 200:
        raise RuntimeError(f"the isolated catalog API rejected a fixture request ({response.status_code})")
    return _object(response.json(), "API response")


def _policies(output: Path, fixtures: dict[str, Any], guest: str, run_id: str, now: datetime) -> dict[str, Any]:
    from app.api import create_app
    from app.auth import AdminService
    from app.service import EmsService
    from fastapi.testclient import TestClient

    invitation = secrets.token_urlsafe(32)
    service = EmsService(valid_invitations={invitation})
    admin = AdminService()
    admin.add_admin("acceptance-builder", secrets.token_urlsafe(32))
    inventory = [{"name": item["installed_name"], "path": guest + "\\" + item["file"],
                  "sha256": item["sha256"], "publisher": "", "version": "1.0", "running": False}
                 for item in fixtures.values()]
    _write_json(output / "fixture-inventory.json", inventory)
    actions = ({}, {"app:" + fixtures["a"]["app_id"]: "block"},
               {"app:" + fixtures["a"]["app_id"]: "block_network"}, {},
               {"app:" + fixtures["a"]["app_id"]: "block"},
               {"app:" + fixtures["b"]["app_id"]: "block"}, {})
    policies = {}
    with TestClient(create_app(service, admin_service=admin, app_catalog_dir=output)) as client:
        registration = _successful(client.post("/fct/api/public/v1/register/", json={
            "devid": "catalog-fixture-" + run_id, "hostname": "synthetic-catalog-fixture", "os": "Windows",
            "invitation": invitation}))
        device = {"Authorization": "Bearer " + registration["device_token"]}
        management = {"Authorization": "Bearer " + admin.issue_token("acceptance-builder", "admin")}
        _successful(client.post("/fct/api/public/v1/inventory/", headers=device, json={
            "client_id": registration["client_id"], "collected_at": now.isoformat(),
            "applications": inventory, "usb_devices": []}))
        for name, decisions in zip(CASES, actions, strict=True):
            _successful(client.post("/api/v1/profiles/Default", headers=management, json={
                "web_filter": {"blocked": []}, "app_control": {"blocked": [], "execution_rules": [], "network_blocked": []},
                "usb_control": {"default_action": "allow", "rules": []}, "app_catalog": {"actions": decisions}}))
            profile = service.get_profile("Default")
            policies[name] = {"vdom": profile.vdom, "version": profile.version,
                              "digest": profile.digest, "body": deepcopy(profile.body)}
    return policies


def build(source: Path, output: Path, *, run_id: str, now: datetime | None = None) -> dict[str, Any]:
    """Build fresh input from a verified production pair of the same source revision."""
    run_id = _run_id(run_id)
    current, packages = _source_receipt(Path(source))
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("the preparation timestamp must include a timezone")
    now = now.astimezone(UTC)
    output = Path(output)
    if output.exists():
        raise ValueError("catalog output already exists; use a fresh directory for each run")
    if not HARNESS.is_file():
        raise ValueError("the catalog guest harness is required")
    output.mkdir(parents=True)
    fixtures = _fixtures(output, run_id)
    guest = "C:\\openems-catalog-" + run_id
    _write_json(output / "app-catalog.json", _synthetic_catalog(fixtures, now))
    policies = _policies(output, fixtures, guest, run_id, now)
    shutil.copyfile(HARNESS, output / HARNESS.name)
    for name in PACKAGES:
        shutil.copyfile(Path(source) / "final-msi" / name, output / name)
    manifest = {"format": 1, "phase": "catalog", "source_revision": current, "run_id": run_id,
                "created_at": now.isoformat(), "guest_work_directory": guest, "packages": packages,
                "fixtures": fixtures, "policies": policies,
                "expansion_proof": {"synthetic_catalog": True, "real_server_api": True,
                                    "guest_transport": "powershell_fixture", "real_server_network_e2e": False,
                                    "inventory_source": "host-compiled owned fixture bytes; synthetic uploaded inventory",
                                    "scope": "Real server API expansion and Windows service enforcement; no panel, live server network, PostgreSQL/Redis or fleet inventory acceptance."},
                "files": {path.name: file_record(path) for path in sorted(output.iterdir()) if path.is_file()}}
    _write_json(output / "acceptance-manifest.json", manifest)
    verify_package(output, expected_revision=current)
    return manifest


def _validate_policies(manifest: dict[str, Any]) -> None:
    from agent.policy import policy_digest

    policies = _object(manifest.get("policies"), "policies")
    if set(policies) != set(CASES):
        raise ValueError("every catalog assignment is required")
    versions = []
    for name in CASES:
        assignment = _object(policies[name], "assignment")
        if type(assignment.get("version")) is not int or assignment["version"] < 1:
            raise ValueError("invalid assignment version")
        versions.append(assignment["version"])
        body = _object(assignment.get("body"), "policy body")
        if assignment.get("digest") != policy_digest(body):
            raise ValueError("assignment digest does not match its body")
    if versions != sorted(set(versions)):
        raise ValueError("assignment versions must increase monotonically")


def _validate_fixtures(manifest: dict[str, Any]) -> None:
    fixtures = _object(manifest.get("fixtures"), "fixtures")
    if set(fixtures) != {"a", "b"}:
        raise ValueError("the two catalog fixtures are required")
    files = manifest["files"]
    for raw_item in fixtures.values():
        item = _object(raw_item, "fixture")
        for field in ("file", "renamed_file"):
            filename = _safe_name(item.get(field))
            if filename not in files or files[filename].get("sha256") != item.get("sha256"):
                raise ValueError("fixture identity does not match the packaged bytes")
        if item["file"] == item["renamed_file"] or "openems" not in str(item.get("installed_name", "")).lower():
            raise ValueError("invalid owned fixture metadata")


def verify_package(directory: Path, *, expected_revision: str | None = None) -> dict[str, Any]:
    """Reject changed, incomplete, unsafe or revision-mismatched input before use."""
    directory = Path(directory)
    manifest_path = directory / "acceptance-manifest.json"
    manifest = _json(manifest_path)
    current = _revision(manifest.get("source_revision"))
    run_id = _run_id(manifest.get("run_id"))
    if expected_revision is not None and current != expected_revision:
        raise ValueError("catalog package source revision mismatch")
    if manifest.get("phase") != "catalog" or manifest.get("format") != 1:
        raise ValueError("unsupported catalog package format")
    if manifest.get("guest_work_directory") != "C:\\openems-catalog-" + run_id:
        raise ValueError("guest directory is not bound to this run")
    files = _object(manifest.get("files"), "files")
    if not {HARNESS.name, *PACKAGES}.issubset(files):
        raise ValueError("catalog harness and production MSI pair are required")
    for name, expected in files.items():
        _verify_file(directory / _safe_name(name), expected)
    delivered = {path.name for path in directory.iterdir()}
    if delivered != set(files) | {"acceptance-manifest.json"}:
        raise ValueError("unreceipted files or directories are present in catalog input")
    packages = _object(manifest.get("packages"), "packages")
    if set(packages) != set(PACKAGES) or any(packages[name] != files[name] for name in PACKAGES):
        raise ValueError("MSI receipts disagree with the input file records")
    _validate_fixtures(manifest)
    _validate_policies(manifest)
    manifest["_manifest_sha256"] = file_record(manifest_path)["sha256"]
    return manifest


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _denied(observation: Any) -> None:
    row = _object(observation, "execution observation")
    _require(row.get("process_created") is False and row.get("started") is False,
             "WDAC must refuse before process creation or sentinel")
    _require(type(row.get("native_error")) is int and row["native_error"] in DENIAL_CODES,
             "a supported native Windows policy refusal is required")
    _require(row.get("exit") == -1, "a refused process cannot have a normal exit")


def _identity(value: Any) -> tuple[int, str]:
    row = _object(value, "assignment identity")
    _require(type(row.get("version")) is int and row["version"] > 0, "invalid observed assignment version")
    digest = row.get("digest")
    _require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
             "invalid observed assignment digest")
    return row["version"], digest


def _ack(evidence: dict[str, Any], assignment: dict[str, Any]) -> None:
    expected = _identity(assignment)
    _require(_identity(evidence.get("assignment")) == expected, "observed assignment does not match the package")
    ack = _object(evidence.get("ack"), "ack")
    _require(_identity(ack) == expected and ack.get("success") is True, "matching positive ACK is required")


def _same_foreign(evidence: dict[str, Any]) -> None:
    before, after = evidence.get("foreign_before"), evidence.get("foreign_after")
    _require(isinstance(before, list) and isinstance(after, list)
             and all(isinstance(item, str) for item in [*before, *after])
             and sorted(before) == sorted(after), "foreign Code Integrity policies were not preserved")


def _utc(value: Any) -> datetime:
    _require(isinstance(value, str), "an observed UTC timestamp is required")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(stamp.tzinfo is not None, "observed timestamp must include a timezone")
    return stamp.astimezone(UTC)


def _number(value: Any) -> float:
    _require(type(value) in {int, float}, "numeric timing evidence is required")
    result = float(value)
    _require(math.isfinite(result), "timing evidence must be finite")
    return result


def _hourly(evidence: dict[str, Any], assignment: dict[str, Any]) -> None:
    before = _object(evidence.get("before"), "hourly before")
    after = _object(evidence.get("after"), "hourly after")
    expected = _identity(assignment)
    _require(_identity(before) == _identity(after) == expected, "hourly assignment changed")
    observations = evidence.get("assignment_observations")
    _require(isinstance(observations, list) and len(observations) >= 2, "hourly assignment observations are incomplete")
    _require(all(_identity(item) == expected for item in observations), "a new push occurred during the hourly wait")
    elapsed = _number(evidence.get("elapsed_seconds"))
    start, finish = _utc(evidence.get("started_utc")), _utc(evidence.get("finished_utc"))
    wall_elapsed = (finish - start).total_seconds()
    _require(elapsed >= 3600 and wall_elapsed >= 3600, "hourly recheck requires 3600 real seconds")
    _require(abs(wall_elapsed - elapsed) <= 30, "monotonic and UTC durations disagree")
    checked_before = _number(before.get("optional_checked_at"))
    checked_after = _number(after.get("optional_checked_at"))
    _require(abs(checked_before - start.timestamp()) <= 90 and abs(checked_after - finish.timestamp()) <= 90,
             "optional_checked_at is inconsistent with observed real time")
    _require(checked_after - checked_before >= 3600, "the optional journal did not advance naturally by an hour")
    admitted = _object(evidence.get("before_admission"), "before-hour admission")
    _require(admitted.get("process_created") is True and admitted.get("native_error") == 0,
             "the later renamed fixture must start before the recheck")
    _denied(evidence.get("after_denial"))


def _network(evidence: dict[str, Any], manifest: dict[str, Any]) -> None:
    before = _object(evidence.get("before"), "network baseline")
    blocked = _object(evidence.get("blocked"), "blocked network")
    released = _object(evidence.get("released"), "released network")
    _require(before.get("target_exit") == before.get("control_exit") == 0, "network baseline failed")
    _require(blocked.get("target_process_created") is True and blocked.get("target_exit") == 42
             and blocked.get("control_exit") == 0, "network denial was masked by process termination or control failure")
    _require(released.get("target_exit") == released.get("control_exit") == 0, "network release failed")
    target = manifest["guest_work_directory"] + "\\" + manifest["fixtures"]["a"]["file"]
    paths = evidence.get("firewall_paths")
    _require(isinstance(paths, list) and len(paths) >= 2
             and all(isinstance(path, str) and path.casefold() == target.casefold() for path in paths),
             "firewall rules did not target only the expected executable")
    _require(evidence.get("control_has_rule") is False, "the network control executable must remain unblocked")


def _cleanup(evidence: dict[str, Any]) -> None:
    _require(evidence.get("msi_exit") == 0, "normal MSI removal failed")
    for field in ("service_present", "watchdog_present", "own_policy_present", "fixture_registry_present"):
        _require(evidence.get(field) is False, f"cleanup did not clear {field}")
    for field in ("nrpt_count", "owned_firewall_rules"):
        _require(type(evidence.get(field)) is int and evidence[field] == 0, f"cleanup left {field}")
    _same_foreign(evidence)


def _evidence(name: str, value: Any, manifest: dict[str, Any]) -> None:
    evidence = _object(value, name + " evidence")
    _require(bool(evidence), name + " evidence is empty")
    if name in {"absent", "all_absent"}:
        _ack(evidence, manifest["policies"]["absent" if name == "absent" else "later"])
        _require(evidence.get("own_policy_present") is False, "an optional absent rule left an owned policy")
        if name == "all_absent":
            _same_foreign(evidence)
    elif name == "network":
        _network(evidence, manifest)
    elif name == "process":
        _require(evidence.get("target_was_running") is True and evidence.get("target_exited") is True
                 and evidence.get("control_still_running") is True, "process termination/control evidence failed")
        target, control = evidence.get("target_pid"), evidence.get("control_pid")
        _require(type(target) is int and type(control) is int and target > 0 and control > 0 and target != control,
                 "distinct observed target/control PIDs are required")
    elif name == "wdac":
        _require(evidence.get("policy_enforced") is True, "the owned WDAC policy must be enforced")
        _denied(evidence.get("original"))
        _denied(evidence.get("renamed"))
    elif name == "hourly":
        _hourly(evidence, manifest["policies"]["later"])
    elif name == "release":
        _ack(evidence, manifest["policies"]["release"])
        _require(evidence.get("original_exit") == evidence.get("renamed_exit") == 0
                 and evidence.get("own_policy_present") is False and evidence.get("firewall_rule_count") == 0,
                 "final release did not restore execution and remove owned policies")
    elif name == "cleanup":
        _cleanup(evidence)


def summarize_report(report: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Re-evaluate observed effects independently; guest passed flags are not evidence."""
    errors = []
    try:
        report = _object(report, "report")
        _require(report.get("run_id") == manifest.get("run_id"), "report run_id mismatch")
        _require(report.get("source_revision") == manifest.get("source_revision"), "report source revision mismatch")
        receipt = _object(report.get("package_receipt"), "report receipt")
        expected = {"source_revision": manifest.get("source_revision"), "packages": manifest.get("packages"),
                    "manifest_sha256": manifest.get("_manifest_sha256")}
        _require(receipt == expected and bool(expected["manifest_sha256"]), "report package receipt mismatch")
        _require(report.get("status") == "passed" and report.get("passed") is True, "report is not completed successfully")
        _require(report.get("error") is None and report.get("cleanup_errors") == [], "report or cleanup contains an error")
        rows = report.get("checks")
        _require(isinstance(rows, list) and len(rows) == len(CHECKS), "the complete set of catalog checks is required")
        checks = {_object(row, "check").get("name"): row for row in rows}
        _require(set(checks) == set(CHECKS), "catalog checks are missing or duplicated")
        for name in CHECKS:
            check = checks[name]
            _require(check.get("status") == "passed", name + " did not pass")
            _evidence(name, check.get("evidence"), manifest)
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        errors.append(str(error))
    return {"passed": not errors, "errors": errors}


def _committed_sources() -> None:
    paths = ["agent-rs", "deploy/test-catalog-sandbox.ps1", "tools/build_catalog_acceptance.py", "tests/test_catalog_sandbox.py"]
    changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--", *paths],
                             cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if changed.strip():
        raise RuntimeError("commit the native and catalog acceptance sources before preparing a real package")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, help="fresh build_final_acceptance output")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--verify", type=Path, metavar="CATALOG_INPUT")
    parser.add_argument("--report", type=Path, help="evaluate a report against --verify input")
    args = parser.parse_args()
    if args.plan:
        print(json.dumps({"phase": "catalog", "guest_only": True, "synthetic_catalog": True,
                          "real_server_api": True, "real_server_network_e2e": False,
                          "compiles_fixtures": True, "executes_fixtures_on_host": False,
                          "executes_controls": False, "required_checks": CHECKS}))
        return 0
    if args.verify:
        manifest = verify_package(args.verify)
        if args.report:
            summary = summarize_report(_json(args.report), manifest)
            print(json.dumps(summary, indent=2))
            return 0 if summary["passed"] else 2
        print(json.dumps({"verified": True, "source_revision": manifest["source_revision"], "run_id": manifest["run_id"]}))
        return 0
    if not args.source or not args.output:
        parser.error("preparation requires --source and --output")
    _committed_sources()
    manifest = build(args.source, args.output, run_id=args.run_id or uuid.uuid4().hex)
    print(json.dumps({"prepared": str(args.output), "source_revision": manifest["source_revision"], "run_id": manifest["run_id"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"catalog acceptance preparation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
