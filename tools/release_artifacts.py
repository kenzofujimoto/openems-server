"""Freeze production artifacts and gate promotion with independently reviewed receipts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

PACKAGES = ("openems-agent.msi", "openems-agent-next.msi")
BINARIES = ("openems-agent.exe", "openems-session.exe")
MANIFEST = "candidate-manifest.json"
SERVER_MANIFEST = "server-image-manifest.json"
UPGRADE_CODE = "0C684B18-7540-4865-9516-567A9E81AA61"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_SERVER_ARCHIVE_BYTES = 1024 * 1024 * 1024
SERVER_SCAN_POLICY = "no-fixable-high-or-critical"
SERVER_RUNTIME_CHECKS = {
    "api": ("health_version", "migrations", "authenticated_policy_publication"),
    "panel": ("login", "csrf", "policy_publication", "reload_persistence"),
}
REQUIRED_ACCEPTANCES = (
    "catalog", "usb", "applications", "session", "locations", "browser-trust",
    "web-actions", "ordered-domains", "safesearch", "antibypass", "pilot",
)


def version_pair(version: str) -> tuple[str, str]:
    """MSI uses three bounded numeric fields; the next patch is an internal fixture."""
    if not isinstance(version, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("Invalid MSI version.")
    major, minor, patch = map(int, version.split("."))
    if major > 255 or minor > 255 or patch >= 65535:
        raise ValueError("MSI version cannot represent the production and upgrade pair.")
    return version, f"{major}.{minor}.{patch + 1}"


def _plain_file(directory: Path, name: str) -> Path:
    if Path(name).name != name or name in {".", ".."}:
        raise ValueError("Artifact names must be plain file names.")
    path = directory / name
    if not path.is_file() or path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError(f"Artifact changed or is missing: {name}")
    return path


def file_record(path: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict[str, str | int]:
    size = path.stat().st_size
    if not 0 < size <= max_bytes:
        raise ValueError(f"Artifact size is outside the accepted bounds: {path.name}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "bytes": size}


def _directory(path: Path) -> Path:
    if not path.is_dir() or path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("The candidate directory must exist and cannot be a link.")
    return path.resolve()


def _source_revision(value: Any) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("The source revision must be a full Git object identity.")


def _msi_identity(metadata: Any, version: str, agent_sha256: str) -> None:
    if not isinstance(metadata, dict):
        raise ValueError("Missing MSI inspection metadata.")
    if metadata.get("product_version") != version:
        raise ValueError("MSI product version mismatch.")
    upgrade = metadata.get("upgrade_code")
    if not isinstance(upgrade, str) or upgrade.strip("{}").upper() != UPGRADE_CODE:
        raise ValueError("MSI upgrade identity mismatch.")
    for field in ("custom_actions", "properties"):
        values = metadata.get(field)
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError("Incomplete MSI table inspection.")
        if len(values) != len(set(values)):
            raise ValueError("Ambiguous MSI table inspection.")
    if {"InjectSetupFailure", "InjectRemovalFailure"} & set(metadata["custom_actions"]):
        raise ValueError("Fault-injection actions cannot be frozen for production.")
    if {"FAIL_SETUP", "FAIL_REMOVAL"} & set(metadata["properties"]):
        raise ValueError("Fault-injection properties cannot be frozen for production.")
    if not {"PrepareAgentSetup", "PrepareAgentRemoval"} <= set(metadata["custom_actions"]):
        raise ValueError("Required installer lifecycle actions are missing.")
    if metadata.get("agent_actions_sha256") != agent_sha256:
        raise ValueError("MSI executable payload mismatch.")
    if metadata.get("signature_status") != "NotSigned":
        raise ValueError("The declared unsigned distribution status was not verified.")


def freeze_candidate(
    directory: Path,
    source_revision: str,
    version: str,
    inspect_msi: Callable[[Path], dict[str, Any]],
) -> dict[str, Any]:
    """Inspect existing packages once; never compile, install, sign or overwrite them."""
    directory = _directory(directory)
    target = directory / MANIFEST
    if target.exists():
        raise ValueError("A candidate manifest already exists; use a new directory.")
    production, upgrade = version_pair(version)
    _source_revision(source_revision)
    packages = {name: file_record(_plain_file(directory, name)) for name in PACKAGES}
    binaries = {name: file_record(_plain_file(directory, name)) for name in BINARIES}
    metadata = {}
    for name, expected_version in zip(PACKAGES, (production, upgrade), strict=True):
        value = inspect_msi(directory / name)
        _msi_identity(value, expected_version, str(binaries["openems-agent.exe"]["sha256"]))
        metadata[name] = value
    # Inspection must not have raced replacement of the files whose hashes will be published.
    for name, record in {**packages, **binaries}.items():
        if file_record(_plain_file(directory, name)) != record:
            raise ValueError(f"Artifact changed during inspection: {name}")
    manifest = {
        "schema_version": 1, "source_revision": source_revision, "version": production,
        "upgrade_fixture_version": upgrade, "distribution_signature": "unsigned",
        "packages": packages, "binaries": binaries, "msi_metadata": metadata,
    }
    with target.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2) + "\n")
    return manifest


def read_candidate(directory: Path, expected_manifest_sha256: str, expected_version: str) -> dict[str, Any]:
    """Use the externally pinned manifest hash before interpreting any of its records."""
    directory = _directory(directory)
    path = _plain_file(directory, MANIFEST)
    if path.stat().st_size > 1024 * 1024 or file_record(path)["sha256"] != expected_manifest_sha256:
        raise ValueError("Candidate manifest mismatch.")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise ValueError("Unsupported candidate manifest.")
    production, upgrade = version_pair(expected_version)
    if (manifest.get("version"), manifest.get("upgrade_fixture_version")) != (production, upgrade):
        raise ValueError("Candidate version mismatch.")
    if manifest.get("distribution_signature") != "unsigned":
        raise ValueError("Candidate distribution signature declaration mismatch.")
    _source_revision(manifest.get("source_revision"))
    for field, names in (("packages", PACKAGES), ("binaries", BINARIES)):
        records = manifest.get(field)
        if not isinstance(records, dict) or set(records) != set(names):
            raise ValueError("Candidate manifest has unexpected artifact names.")
        for name, record in records.items():
            if not isinstance(record, dict) or set(record) != {"sha256", "bytes"}:
                raise ValueError("Invalid candidate file record.")
            if type(record["bytes"]) is not int or not isinstance(record["sha256"], str):
                raise ValueError("Invalid candidate file identity.")
            if record != file_record(_plain_file(directory, name)):
                raise ValueError(f"Candidate artifact changed or mismatch: {name}")
    metadata = manifest.get("msi_metadata")
    if not isinstance(metadata, dict) or set(metadata) != set(PACKAGES):
        raise ValueError("Candidate manifest lacks MSI inspection evidence.")
    for name, version in zip(PACKAGES, (production, upgrade), strict=True):
        _msi_identity(metadata[name], version, manifest["binaries"]["openems-agent.exe"]["sha256"])
    return manifest


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def read_server_candidate(
    directory: Path, expected_manifest_sha256: str, expected_version: str, expected_source_revision: str,
) -> dict[str, Any]:
    """Verify the pinned existing image archive; never build, load or extract an image."""
    try:
        directory = _directory(directory)
        path = _plain_file(directory, SERVER_MANIFEST)
        if not _sha256(expected_manifest_sha256):
            raise ValueError("Invalid pinned manifest hash.")
        # Hash and decode the same bounded bytes so a changed manifest cannot redefine identity.
        with path.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected_manifest_sha256:
            raise ValueError("Pinned manifest mismatch.")
        server = json.loads(data)
        fields = {"schema_version", "version", "source_revision", "status", "local_tag", "image_id", "platform", "file", "sha256", "bytes", "inspection"}
        if not isinstance(server, dict) or set(server) != fields or type(server["schema_version"]) is not int or server["schema_version"] != 1:
            raise ValueError("Unsupported manifest schema.")
        version_pair(expected_version)
        _source_revision(expected_source_revision)
        if server["version"] != expected_version or server["source_revision"] != expected_source_revision:
            raise ValueError("Source or version mismatch.")
        if server["status"] != "image_built_runtime_acceptance_pending" or not isinstance(server["local_tag"], str) or not server["local_tag"]:
            raise ValueError("Invalid frozen image declaration.")
        if not isinstance(server["image_id"], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", server["image_id"]) is None:
            raise ValueError("An immutable image identity is required.")
        if server["platform"] != "linux/amd64" or server["file"] != f"openems-server-{expected_version}-linux-amd64.tar.gz":
            raise ValueError("Unexpected image platform or archive name.")
        inspection = server["inspection"]
        if (
            not isinstance(inspection, dict) or set(inspection) != {"version", "panel_present", "migration_008_present"}
            or inspection["version"] != expected_version or inspection["panel_present"] is not True
            or inspection["migration_008_present"] is not True
        ):
            raise ValueError("Missing frozen image inspection evidence.")
        if type(server["bytes"]) is not int or not _sha256(server["sha256"]):
            raise ValueError("Invalid archive identity.")
        actual = file_record(_plain_file(directory, server["file"]), max_bytes=MAX_SERVER_ARCHIVE_BYTES)
        if actual != {"sha256": server["sha256"], "bytes": server["bytes"]}:
            raise ValueError("Frozen archive changed or mismatch.")
    except (ValueError, OSError) as error:
        raise ValueError(f"Server candidate refused: {error}") from error
    return server


def _server_passed(value: Any) -> bool:
    return (
        isinstance(value, dict) and value.get("passed") is True and not value.get("error")
        and value.get("status", "passed") == "passed" and value.get("cleanup_errors", []) == []
    )


def _server_evidence(value: Any, identity: Mapping[str, Any]) -> bool:
    return (
        _server_passed(value) and _sha256(value.get("evidence_sha256"))
        and value.get("server_receipt") == identity and type(value["server_receipt"]["bytes"]) is int
    )


def _verify_server_report(server: Mapping[str, Any], manifest_sha256: str, report: Any) -> None:
    identity = {name: server[name] for name in ("source_revision", "version", "image_id", "platform", "file", "sha256", "bytes")}
    identity["manifest_sha256"] = manifest_sha256
    if (
        not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1
        or not _server_passed(report) or report.get("cleanup_errors") != []
        or report.get("server_receipt") != identity or type(report["server_receipt"]["bytes"]) is not int
    ):
        raise ValueError("Server acceptance is pending, failed or tied to different image bytes.")
    review = report.get("independent_review")
    if (
        not _server_passed(review) or not _sha256(review.get("evidence_sha256"))
        or not isinstance(review.get("reviewer"), str) or not review["reviewer"].strip()
    ):
        raise ValueError("Server independent review is missing or failed.")
    scan = report.get("scan")
    if (
        not _server_evidence(scan, identity) or scan.get("policy") != SERVER_SCAN_POLICY
        or any(type(scan.get(field)) is not int or scan[field] != 0 for field in ("fixable_high", "fixable_critical"))
        or type(scan.get("unfixed_findings_reported")) is not int or scan["unfixed_findings_reported"] < 0
    ):
        raise ValueError("Server image scan evidence or fixable HIGH/CRITICAL policy failed.")
    acceptance = report.get("acceptance")
    for phase, checks in SERVER_RUNTIME_CHECKS.items():
        value = acceptance.get(phase) if isinstance(acceptance, dict) else None
        if (
            not _server_evidence(value, identity) or value.get("real_runtime") is not True
            or not isinstance(value.get("checks"), dict) or any(value["checks"].get(name) is not True for name in checks)
        ):
            raise ValueError(f"Server real runtime acceptance remains pending or failed: {phase}")


def release_asset_names(
    manifest: Mapping[str, Any], reports: Mapping[str, Any], *, server_directory: Path | None = None,
    server_manifest_sha256: str | None = None, server_report: Mapping[str, Any] | None = None,
) -> tuple[str, ...]:
    """Promote only the exact agent and image bytes with complete independently reviewed gates.

    Legacy two-argument callers fail closed until they supply all three server keywords.
    Runtime and scan receipts must identify the pinned image archive and manifest, not a tag.
    """
    for phase in REQUIRED_ACCEPTANCES:
        report = reports.get(phase)
        receipt = report.get("package_receipt") if isinstance(report, dict) else None
        if (
            not isinstance(report, dict) or report.get("passed") is not True
            or report.get("cleanup_errors") != [] or report.get("error") or report.get("status") == "failed"
            or not isinstance(receipt, dict) or receipt.get("source_revision") != manifest.get("source_revision")
            or receipt.get("packages") != manifest.get("packages")
        ):
            raise ValueError(f"Release acceptance remains pending or failed: {phase}")
    if server_directory is None or server_manifest_sha256 is None or server_report is None:
        raise ValueError("Server image manifest and independent acceptance receipt are required.")
    server = read_server_candidate(server_directory, server_manifest_sha256, manifest.get("version"), manifest.get("source_revision"))
    _verify_server_report(server, server_manifest_sha256, server_report)
    return ("openems-agent.msi", MANIFEST, server["file"], SERVER_MANIFEST, "SHA256SUMS")
