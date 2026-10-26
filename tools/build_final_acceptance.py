#!/usr/bin/env python3
"""Build one current production MSI pair for all pending Windows acceptances.

Run only after the final native sources are committed. This does not start Sandbox or install an MSI.
The per-input manifest pins the harness, launcher, binaries and packages by SHA-256. The wrapper
checks those bytes before invoking a harness and stamps only reports produced in that invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from sandbox_package import ROOT, SANDBOX

PHASES = ("session", "locations", "usb", "applications")
PACKAGES = ("openems-agent.msi", "openems-agent-next.msi")
REPORTS = ("session-phase1.json", "session-result.json", "locations-result.json",
           "usb-result.json", "applications-result.json")


def summarize_results(paths: list[Path], manifest: dict | None = None) -> dict:
    """Missing, partial, stale or hardware-pending reports never become successful acceptance."""
    accepted, pending, failed = [], [], []
    for path in paths:
        try:
            report = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            pending.append(path.name)
            continue
        if not isinstance(report, dict):
            pending.append(path.name)
            continue
        receipt = report.get("package_receipt", {})
        current = manifest is None or (
            isinstance(receipt, dict) and receipt.get("source_revision") == manifest.get("source_revision")
            and receipt.get("packages") == manifest.get("packages"))
        failed_report = report.get("status") == "failed" or report.get("error") or report.get("cleanup_errors")
        physical_complete = (report.get("physical_acceptance_pending") is False if path.name == "usb-result.json"
                             else not report.get("physical_acceptance_pending"))
        if failed_report:
            failed.append(path.name)
        elif report.get("passed") is True and physical_complete and current:
            accepted.append(path.name)
        else:
            pending.append(path.name)
    return {"passed": bool(paths) and not pending and not failed, "accepted": accepted,
            "pending": pending, "failed": failed}


def file_record(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def checked(arguments: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, cwd=ROOT, env=environment, check=True)


def revision() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def require_committed_native_sources() -> None:
    changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--", "agent-rs"],
                             cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if changed.strip():
        raise RuntimeError("commit all native sources before building final acceptance packages")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--output", type=Path, default=SANDBOX)
    parser.add_argument("--wix", type=Path, default=ROOT / ".venv/wix-tools/wix.exe")
    parser.add_argument("--dotnet-root", type=Path, default=ROOT / ".venv/dotnet-sdk")
    parser.add_argument("--summarize", type=Path, metavar="RESULTS_DIRECTORY")
    args = parser.parse_args()
    if args.plan:
        print(json.dumps({"phases": PHASES, "packages": PACKAGES, "fresh_build": True,
                          "launches_sandbox": False, "reports": REPORTS}))
        return 0
    output = args.output.resolve()
    if args.summarize:
        manifest_path = output / "acceptance-manifest.json"
        if not manifest_path.is_file():
            raise RuntimeError("the final acceptance manifest is required before summarizing results")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        summary = summarize_results([args.summarize / name for name in REPORTS], manifest)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["passed"] else 2
    if os.name != "nt":
        raise RuntimeError("build Windows acceptance packages on Windows with WiX and the .NET runtime")
    require_committed_native_sources()
    source_revision = revision()
    checked(["cargo", "build", "--release", "--manifest-path", str(ROOT / "agent-rs/Cargo.toml")])
    output.mkdir(parents=True, exist_ok=True)
    packages = output / "final-msi"
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet_root.resolve()))
    for extra in ([], ["-Next"]):
        checked(["powershell.exe", "-NoProfile", "-File", str(ROOT / "tools/build-msi-fixtures.ps1"),
                 "-Production", "-OutputDirectory", str(packages), "-Wix", str(args.wix.resolve()), *extra],
                environment=environment)
    records = {name: file_record(packages / name) for name in PACKAGES}
    manifest = {"source_revision": source_revision, "packages": records, "phases": {}}
    results = output / "results"
    for phase in PHASES:
        directory = output / f"{phase}-input"
        if phase in ("session", "locations"):
            checked([sys.executable, str(ROOT / f"tools/build_{phase}_sandbox.py"),
                     "--output", str(directory), "--results", str(results)])
            harness = f"test-{phase}-sandbox.ps1"
            arguments: list[str] = []
        else:
            checked([sys.executable, str(ROOT / "tools/build_controls_sandbox.py"), "--kind", phase,
                     "--output", str(directory), "--results", str(results)])
            harness = "test-controls-sandbox.ps1"
            arguments = ["-Kind", phase.capitalize()]
        for name in PACKAGES:
            shutil.copyfile(packages / name, directory / name)
        wrapper = "invoke-final-acceptance.ps1"
        shutil.copyfile(ROOT / "deploy" / wrapper, directory / wrapper)
        launcher = directory / f"RUN-{phase.upper()}-TEST.cmd"
        launcher.write_text(
            "@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "
            f"C:\\openems-input\\{wrapper} -Phase {phase} -OutputDirectory C:\\openems-results\r\n",
            encoding="ascii", newline="")
        phase_manifest = {
            "source_revision": source_revision, "phase": phase, "harness": harness, "arguments": arguments,
            "packages": records, "files": {path.name: file_record(path) for path in directory.iterdir()
                                           if path.is_file() and path.name != "acceptance-manifest.json"},
        }
        (directory / "acceptance-manifest.json").write_text(json.dumps(phase_manifest, indent=2), encoding="utf-8")
        manifest["phases"][phase] = phase_manifest
    (output / "acceptance-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"prepared one current MSI pair for {', '.join(PHASES)}; no Sandbox was started")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"acceptance preparation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
