"""A broken scanner or an old report must never approve a security gate."""

from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

import pytest

from tools import security_scan as scanner


ARTIFACTS = (
    "trivy-config.json", "trivy-image.json", "trivy-image.sarif", "sbom.cdx.json",
)


def clean_reports() -> dict[str, object]:
    return {
        "trivy-config.json": {"SchemaVersion": 2, "Results": []},
        "trivy-image.json": {"SchemaVersion": 2, "Results": []},
        "trivy-image.sarif": {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}],
        },
        "sbom.cdx.json": {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "container", "name": "openems:test"}},
            "components": [],
        },
    }


class ScannerHarness:
    """Replace only process boundaries; the gates still parse real temporary files."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch):
        self.out = root / "reports"
        self.src = root / "src"
        self.out.mkdir()
        self.src.mkdir()
        (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        accepted_path = root / "accepted.json"
        accepted_path.write_text('{"findings": []}', encoding="utf-8")
        self.accepted = scanner.Accepted(accepted_path, date(2026, 10, 27))
        self.reports = {name: json.dumps(report) for name, report in clean_reports().items()}
        self.exit_codes: dict[str, int] = {}
        self.zizmor_exit = 0
        self.zizmor_stdout = "[]"
        monkeypatch.setattr(scanner, "ROOT", root)
        monkeypatch.setattr(scanner, "run", self.run)
        monkeypatch.setattr(scanner, "docker", self.docker)
        monkeypatch.setattr(scanner.subprocess, "run", self.hadolint)

    def accept(self, tool: str, identifier: str) -> None:
        self.accepted.items[(tool, identifier)] = {
            "tool": tool, "id": identifier, "expires": "2027-01-31",
            "reason": "Reviewed fixture finding accepted for this test only.",
        }

    def write_report(self, name: str) -> subprocess.CompletedProcess:
        content = self.reports.get(name)
        if content is not None:
            (self.out / name).write_text(content, encoding="utf-8")
        return subprocess.CompletedProcess(["docker"], self.exit_codes.get(name, 0), "", "")

    def docker(self, image: str, args: list[str], **_kwargs) -> subprocess.CompletedProcess:
        if image == scanner.IMAGES["zizmor"]:
            return subprocess.CompletedProcess(["docker"], self.zizmor_exit, self.zizmor_stdout, "")
        assert image == scanner.IMAGES["trivy"]
        return self.write_report(Path(args[args.index("-o") + 1]).name)

    def run(self, command: list[str], **_kwargs) -> subprocess.CompletedProcess:
        if "-o" in command:
            return self.write_report(Path(command[command.index("-o") + 1]).name)
        return subprocess.CompletedProcess(command, 0, "", "")

    @staticmethod
    def hadolint(command: list[str], **_kwargs) -> subprocess.CompletedProcess:
        assert scanner.IMAGES["hadolint"] in command
        return subprocess.CompletedProcess(command, 0, b"[]", b"")

    def workflows(self) -> scanner.Gate:
        return scanner.gate_workflows(self.out, self.src, self.accepted, self.out / "scan.log")

    def container(self) -> scanner.Gate:
        return scanner.gate_container(self.out, self.src, self.accepted, self.out / "scan.log")


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ScannerHarness:
    return ScannerHarness(tmp_path, monkeypatch)


def test_zizmor_clean_completed_audit_passes(harness):
    assert harness.workflows().passed


@pytest.mark.parametrize("exit_code", [1, 2, 3, 125])
def test_zizmor_execution_failure_rejects_even_valid_empty_json(harness, exit_code):
    harness.zizmor_exit = exit_code
    assert not harness.workflows().passed


@pytest.mark.parametrize("exit_code", [0, 125])
def test_zizmor_empty_output_is_not_a_completed_audit(harness, exit_code):
    harness.zizmor_exit = exit_code
    harness.zizmor_stdout = ""
    assert not harness.workflows().passed


@pytest.mark.parametrize("output", ["not json", "null", "{}", "[null]"])
def test_zizmor_invalid_report_is_rejected(harness, output):
    harness.zizmor_stdout = output
    assert not harness.workflows().passed


@pytest.mark.parametrize("exit_code", [13, 14])
@pytest.mark.parametrize("accepted", [False, True])
def test_zizmor_completed_audit_preserves_finding_and_exception_policy(harness, exit_code, accepted):
    harness.zizmor_exit = exit_code
    harness.zizmor_stdout = json.dumps([{
        "ident": "unpinned-uses", "determinations": {"severity": "high"},
        "locations": [{"symbolic": {"key": {"Local": {"given_path": "ci.yml"}}}}],
    }])
    if accepted:
        harness.accept("zizmor", "unpinned-uses")
    assert harness.workflows().passed is accepted


def test_zizmor_findings_exit_with_no_findings_is_rejected(harness):
    harness.zizmor_exit = 14
    assert not harness.workflows().passed


def test_complete_clean_container_scan_passes(harness):
    result = harness.container()
    assert result.passed
    assert "SBOM: sbom.cdx.json (CycloneDX)" in result.details


@pytest.mark.parametrize("artifact", ARTIFACTS)
@pytest.mark.parametrize("failure", ["execution", "missing", "invalid-json", "invalid-shape", "stale"])
def test_container_requires_fresh_valid_reports_from_successful_scanners(harness, artifact, failure):
    if failure == "execution":
        harness.exit_codes[artifact] = 125
    elif failure in {"missing", "stale"}:
        if failure == "stale":
            (harness.out / artifact).write_text(harness.reports[artifact], encoding="utf-8")
        del harness.reports[artifact]
    else:
        harness.reports[artifact] = "not json" if failure == "invalid-json" else "{}"
    assert not harness.container().passed


@pytest.mark.parametrize("artifact,report", [
    ("trivy-config.json", {"SchemaVersion": 2, "Results": {}}),
    ("trivy-image.json", {"SchemaVersion": 2, "Results": [None]}),
    ("trivy-image.sarif", {"version": "2.1.0", "runs": []}),
    ("trivy-image.sarif", {"version": "2.1.0", "runs": [{"results": []}]}),
    ("sbom.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": {}}),
])
def test_container_rejects_malformed_report_collections(harness, artifact, report):
    harness.reports[artifact] = json.dumps(report)
    assert not harness.container().passed


@pytest.mark.parametrize("accepted", [False, True])
def test_container_preserves_misconfiguration_policy(harness, accepted):
    harness.reports["trivy-config.json"] = json.dumps({
        "SchemaVersion": 2,
        "Results": [{"Target": "Dockerfile", "Misconfigurations": [{
            "ID": "AVD-DS-0002", "Status": "FAIL", "Title": "Image runs as root",
        }]}],
    })
    if accepted:
        harness.accept("trivy", "AVD-DS-0002")
    assert harness.container().passed is accepted


@pytest.mark.parametrize("accepted", [False, True])
def test_container_preserves_fixable_high_vulnerability_policy(harness, accepted):
    harness.reports["trivy-image.json"] = json.dumps({
        "SchemaVersion": 2,
        "Results": [{"Target": "Python", "Vulnerabilities": [{
            "PkgName": "fixture-package", "InstalledVersion": "1.0", "FixedVersion": "1.1",
            "Severity": "HIGH", "VulnerabilityID": "CVE-2099-0001",
        }]}],
    })
    if accepted:
        harness.accept("trivy", "CVE-2099-0001")
    assert harness.container().passed is accepted


def test_container_does_not_announce_a_missing_sbom(harness):
    del harness.reports["sbom.cdx.json"]
    assert not any(detail.startswith("SBOM:") for detail in harness.container().details)
