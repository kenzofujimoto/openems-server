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
UPGRADE_CODE = "0C684B18-7540-4865-9516-567A9E81AA61"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
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


def file_record(path: Path) -> dict[str, str | int]:
    size = path.stat().st_size
    if not 0 < size <= MAX_ARTIFACT_BYTES:
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


def release_asset_names(manifest: Mapping[str, Any], reports: Mapping[str, Any]) -> tuple[str, ...]:
    """Only independently reviewed receipts for this exact pair can authorize promotion."""
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
    return ("openems-agent.msi", MANIFEST, "SHA256SUMS")
