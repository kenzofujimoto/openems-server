#!/usr/bin/env python3
"""Run the repository security gates, each scanner in a digest-pinned container.

    python tools/security_scan.py                       # every static gate
    python tools/security_scan.py --only sast,secrets   # selected gates
    python tools/security_scan.py --dast                # static gates plus ZAP on a disposable stack
    python tools/security_scan.py --only dast           # DAST only

Gates: secrets (gitleaks, full history), sast (Semgrep registry packs + .semgrep/), dependencies
(pip-audit, osv-scanner, cargo-deny), container (hadolint, Trivy config and image, CycloneDX SBOM),
workflows (actionlint, zizmor) and dast (ZAP baseline and authenticated API scan). Reports go to
.venv/security-reports/<timestamp>/ unless --output is given. The exit code is 1 when a gate fails.
Reviewed exceptions live in security/accepted-findings.json and expire.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Pinned by digest; Dependabot does not track these, so refresh them deliberately and re-run.
IMAGES = {
    "gitleaks": "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    "semgrep": "semgrep/semgrep@sha256:3db5c7af55eb1f512eac0abf0ab69a97b52c74b5e9a27314c221aee1a78d7ab2",
    "trivy": "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c",
    "osv-scanner": "ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0",
    "hadolint": "hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d",
    "zap": "ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238",
    "actionlint": "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667",
    "zizmor": "ghcr.io/zizmorcore/zizmor@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9",
    "python": "python@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c",
}
PIP_AUDIT = "pip-audit==2.10.1"
SEMGREP_PACKS = ("p/default", "p/owasp-top-ten", "p/python", "p/typescript", "p/react", "p/rust",
                 "p/dockerfile", "p/github-actions", "p/secrets")
LOCKFILES = ("requirements.txt", "web/package-lock.json", "agent-rs/Cargo.lock")
SCAN_IMAGE = "openems-server:security-scan"
GATES = ("secrets", "sast", "dependencies", "container", "workflows", "dast")
DEFAULT_GATES = GATES[:-1]


@dataclass
class Gate:
    name: str
    passed: bool = True
    details: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.passed = False
        self.details.append("FAIL " + message)

    def note(self, message: str) -> None:
        self.details.append(message)


class Accepted:
    """Reviewed exceptions; an expired entry is itself a failure."""

    def __init__(self, path: Path, today: date):
        data = json.loads(path.read_text(encoding="utf-8"))
        self.items = {(item["tool"], str(item["id"])): item for item in data["findings"]}
        self.expired = [item for item in data["findings"] if date.fromisoformat(item["expires"]) < today]

    def covers(self, tool: str, identifier: str) -> bool:
        item = self.items.get((tool, str(identifier)))
        return item is not None and item not in self.expired


def mount(path: Path) -> str:
    return path.resolve().as_posix()


def run(command: list[str], *, log: Path, timeout: int = 1800, env: dict | None = None,
        check: bool = False) -> subprocess.CompletedProcess:
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, check=False,
                            encoding="utf-8", errors="replace")
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(command[:6])} ... ({time.monotonic() - started:.0f}s, exit {result.returncode})\n")
        handle.write(result.stdout[-20000:] + result.stderr[-20000:] + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{command[0]} {command[1] if len(command) > 1 else ''} failed (exit {result.returncode}); see {log}")
    return result


def docker(image: str, args: list[str], *, volumes: dict[Path, str], log: Path, network: str | None = None,
           entrypoint: str | None = None, user_root: bool = False, timeout: int = 1800) -> subprocess.CompletedProcess:
    command = ["docker", "run", "--rm"]
    if network:
        command += ["--network", network]
    if entrypoint:
        command += ["--entrypoint", entrypoint]
    if user_root:
        command += ["-u", "root"]
    for host, target in volumes.items():
        command += ["-v", f"{mount(host)}:{target}"]
    return run([*command, image, *args], log=log, timeout=timeout)


def snapshot(output: Path) -> Path:
    """Copy tracked and untracked-but-not-ignored files: what a commit would contain, never .venv or secrets."""
    target = output / "src"
    if target.exists():
        shutil.rmtree(target)
    listed = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                            capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    for name in filter(None, listed):
        source = ROOT / name
        if source.is_file():
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    return target


def load_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def gate_secrets(out: Path, accepted: Accepted, log: Path) -> Gate:
    gate = Gate("secrets")
    result = docker(IMAGES["gitleaks"], ["git", "--no-banner", "--redact", "--config", "/repo/.gitleaks.toml",
                                         "--report-format", "sarif", "--report-path", "/out/gitleaks.sarif", "/repo"],
                    volumes={ROOT: "/repo:ro", out: "/out"}, log=log)
    report = load_json(out / "gitleaks.sarif") or {}
    leaks = [r for run_ in report.get("runs", []) for r in run_.get("results", [])]
    if result.returncode not in (0, 1) or not report:
        gate.fail(f"gitleaks did not complete (exit {result.returncode})")
    for leak in leaks:
        location = leak["locations"][0]["physicalLocation"]
        gate.fail(f"{leak['ruleId']} in {location['artifactLocation']['uri']}:{location['region']['startLine']}")
    gate.note(f"gitleaks: {len(leaks)} finding(s) across the Git history")
    return gate


def gate_sast(out: Path, src: Path, accepted: Accepted, log: Path) -> Gate:
    gate = Gate("sast")
    configs = [arg for pack in SEMGREP_PACKS for arg in ("--config", pack)] + ["--config", "/src/.semgrep"]
    result = docker(IMAGES["semgrep"], ["semgrep", "scan", "--metrics=off", "--disable-version-check", *configs,
                                        "--json-output=/out/semgrep.json", "--sarif-output=/out/semgrep.sarif", "/src"],
                    volumes={src: "/src:ro", out: "/out"}, log=log)
    report = load_json(out / "semgrep.json")
    if not isinstance(report, dict) or result.returncode not in (0, 1):
        gate.fail(f"semgrep did not complete (exit {result.returncode})")
        return gate
    findings = report.get("results", [])
    blocking = [item for item in findings if item["extra"]["severity"] == "ERROR"
                and not accepted.covers("semgrep", f"{item['check_id']}:{item['path']}:{item['start']['line']}")]
    for item in blocking:
        gate.fail(f"{item['check_id'].rsplit('.', 1)[-1]} {item['path']}:{item['start']['line']}")
    counts: dict[str, int] = {}
    for item in findings:
        counts[item["extra"]["severity"]] = counts.get(item["extra"]["severity"], 0) + 1
    gate.note(f"semgrep: {counts or 'no findings'}; ERROR blocks, WARNING/INFO are reported in SARIF")
    for error in report.get("errors", []):
        if error.get("level") == "error":
            gate.fail(f"semgrep error: {str(error.get('message', ''))[:160]}")
    return gate


def gate_dependencies(out: Path, src: Path, accepted: Accepted, log: Path, *, cargo_deny: bool) -> Gate:
    gate = Gate("dependencies")
    script = (f"pip install -q --disable-pip-version-check --root-user-action=ignore {PIP_AUDIT} >/dev/null && "
              "pip-audit -r /src/requirements.txt --require-hashes --disable-pip --no-deps --progress-spinner off "
              "-f json -o /out/pip-audit-runtime.json; "
              "pip-audit -r /src/requirements-dev.txt --progress-spinner off -f json -o /out/pip-audit-dev.json; true")
    docker(IMAGES["python"], ["-c", script], volumes={src: "/src:ro", out: "/out"}, log=log, entrypoint="sh")
    for name in ("pip-audit-runtime.json", "pip-audit-dev.json"):
        report = load_json(out / name)
        if not isinstance(report, dict):
            gate.fail(f"{name} missing: pip-audit did not complete")
            continue
        for dependency in report.get("dependencies", []):
            for vuln in dependency.get("vulns", []):
                if not accepted.covers("pip-audit", vuln["id"]):
                    gate.fail(f"{dependency['name']} {dependency['version']}: {vuln['id']} (fix {vuln.get('fix_versions')})")
    args = ["scan", "source", "--format", "json", "--output-file", "/out/osv.json"]
    for lockfile in LOCKFILES:
        args += ["-L", f"/src/{lockfile}"]
    result = docker(IMAGES["osv-scanner"], args, volumes={src: "/src:ro", out: "/out"}, log=log)
    report = load_json(out / "osv.json")
    if not isinstance(report, dict) or result.returncode not in (0, 1):
        gate.fail(f"osv-scanner did not complete (exit {result.returncode})")
    else:
        for source in report.get("results", []):
            for package in source.get("packages", []):
                for vuln in package.get("vulnerabilities", []):
                    if not accepted.covers("osv", vuln["id"]) and not any(
                            accepted.covers("pip-audit", alias) for alias in [vuln["id"], *vuln.get("aliases", [])]):
                        gate.fail(f"{package['package']['name']} {package['package']['version']}: {vuln['id']}")
    if cargo_deny:
        binary = shutil.which("cargo-deny") or shutil.which("cargo-deny.exe")
        if binary is None:
            gate.fail("cargo-deny is not installed (cargo install --locked cargo-deny), or pass --no-cargo-deny where CI runs it")
        else:
            result = run(["cargo", "deny", "--manifest-path", str(ROOT / "agent-rs" / "Cargo.toml"), "check",
                          "advisories", "bans", "licenses", "sources"], log=log)
            if result.returncode != 0:
                gate.fail("cargo deny check failed; see " + log.name)
            else:
                gate.note("cargo-deny: advisories, bans, licenses and sources ok")
    else:
        gate.note("cargo-deny skipped here by request (the CI dependency job runs it)")
    gate.note("pip-audit runtime and dev, osv-scanner on " + ", ".join(LOCKFILES))
    return gate


def _records_have_fields(records: object, fields: tuple[str, ...]) -> bool:
    return isinstance(records, list) and all(
        isinstance(record, dict) and all(isinstance(record.get(key), str) for key in fields)
        for record in records
    )


def _valid_trivy_report(report: dict) -> bool:
    if report.get("SchemaVersion") != 2 or not _records_have_fields(report.get("Results"), ("Target",)):
        return False
    for target in report["Results"]:
        for name, fields in (
            ("Misconfigurations", ("ID", "Status", "Title")),
            ("Vulnerabilities", ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")),
        ):
            records = target.get(name)
            if records is not None and not _records_have_fields(records, fields):
                return False
    return True


def _valid_sarif_report(report: dict) -> bool:
    runs = report.get("runs")
    if report.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
        return False
    for run_ in runs:
        if not isinstance(run_, dict) or not isinstance(run_.get("tool"), dict):
            return False
        driver = run_["tool"].get("driver")
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            return False
        if not _records_have_fields(run_.get("results", []), ()):
            return False
    return True


def _valid_sbom_report(report: dict) -> bool:
    return (
        report.get("bomFormat") == "CycloneDX"
        and isinstance(report.get("specVersion"), str)
        and bool(report["specVersion"])
        and type(report.get("version")) is int
        and report["version"] > 0
        and _records_have_fields(report.get("components", []), ("name", "type"))
    )


def _checked_report(path: Path, result: subprocess.CompletedProcess, gate: Gate,
                    validator: Callable[[dict], bool]) -> dict | None:
    report = load_json(path)
    if result.returncode != 0 or not isinstance(report, dict) or not validator(report):
        gate.fail(f"{path.name}: scanner did not complete or report is invalid (exit {result.returncode})")
        return None
    return report


def gate_container(out: Path, src: Path, accepted: Accepted, log: Path) -> Gate:
    gate = Gate("container")
    # Never let a previous invocation's artifacts stand in for a failed current scan.
    for name in ("hadolint.json", "trivy-config.json", "trivy-image.json", "trivy-image.sarif", "sbom.cdx.json"):
        (out / name).unlink(missing_ok=True)
    with (ROOT / "Dockerfile").open("rb") as dockerfile:
        result = subprocess.run(["docker", "run", "--rm", "-i", IMAGES["hadolint"], "hadolint", "--failure-threshold",
                                 "warning", "-f", "json", "-"], stdin=dockerfile, capture_output=True, timeout=600, check=False)
    (out / "hadolint.json").write_bytes(result.stdout)
    if result.returncode != 0:
        gate.fail("hadolint: " + result.stdout.decode("utf-8", "replace")[:400])
    result = docker(IMAGES["trivy"], ["config", "--quiet", "--severity", "HIGH,CRITICAL", "--format", "json",
                                      "-o", "/out/trivy-config.json", "/src"], volumes={src: "/src:ro", out: "/out"}, log=log)
    report = _checked_report(out / "trivy-config.json", result, gate, _valid_trivy_report)
    if report is None:
        return gate
    for target in report["Results"]:
        for item in target.get("Misconfigurations") or []:
            if item.get("Status") == "FAIL" and not accepted.covers("trivy", item["ID"]):
                gate.fail(f"{target['Target']}: {item['ID']} {item['Title']}")
    built = run(["docker", "build", "-t", SCAN_IMAGE, "."], log=log, timeout=3600)
    if built.returncode != 0:
        gate.fail("docker build failed; see " + log.name)
        return gate
    socket = {"//var/run/docker.sock" if sys.platform == "win32" else "/var/run/docker.sock": "/var/run/docker.sock"}
    base = ["docker", "run", "--rm", "-v", f"{next(iter(socket))}:/var/run/docker.sock", "-v", f"{mount(out)}:/out",
            "-v", "openems-trivy-cache:/root/.cache", IMAGES["trivy"], "image", "--quiet", "--timeout", "20m"]
    result = run([*base, "--format", "json", "-o", "/out/trivy-image.json", SCAN_IMAGE], log=log)
    report = _checked_report(out / "trivy-image.json", result, gate, _valid_trivy_report)
    if report is None:
        return gate
    result = run([*base, "--format", "sarif", "--ignore-unfixed", "--severity", "HIGH,CRITICAL", "-o",
                  "/out/trivy-image.sarif", SCAN_IMAGE], log=log)
    _checked_report(out / "trivy-image.sarif", result, gate, _valid_sarif_report)
    result = run([*base, "--format", "cyclonedx", "-o", "/out/sbom.cdx.json", SCAN_IMAGE], log=log)
    sbom = _checked_report(out / "sbom.cdx.json", result, gate, _valid_sbom_report)
    unfixed = 0
    for target in report.get("Results", []):
        for vuln in target.get("Vulnerabilities") or []:
            if not vuln.get("FixedVersion"):
                unfixed += 1
            elif vuln["Severity"] in ("HIGH", "CRITICAL") and not accepted.covers("trivy", vuln["VulnerabilityID"]):
                gate.fail(f"{vuln['PkgName']} {vuln['InstalledVersion']} -> {vuln['FixedVersion']}: {vuln['VulnerabilityID']}")
    gate.note(f"image: fixable HIGH/CRITICAL block; {unfixed} finding(s) without an upstream fix are reported only")
    if sbom is not None:
        gate.note("SBOM: sbom.cdx.json (CycloneDX)")
    return gate


def gate_workflows(out: Path, src: Path, accepted: Accepted, log: Path) -> Gate:
    gate = Gate("workflows")
    # The snapshot has no .git, so actionlint gets the workflow files explicitly.
    workflows = sorted(f".github/workflows/{path.name}" for path in (src / ".github" / "workflows").glob("*.yml"))
    result = run(["docker", "run", "--rm", "-v", f"{mount(src)}:/repo:ro", "-w", "/repo", IMAGES["actionlint"], *workflows],
                 log=log, timeout=600)
    if result.returncode != 0:
        gate.fail("actionlint: " + (result.stdout + result.stderr).strip()[:600])
    result = docker(IMAGES["zizmor"], ["--format", "json", "--min-severity", "medium", "/repo/.github/workflows"],
                    volumes={src: "/repo:ro"}, log=log, timeout=600)
    (out / "zizmor.json").write_text(result.stdout, encoding="utf-8")
    try:
        findings = json.loads(result.stdout)
    except ValueError:
        findings = None
    # Zizmor reserves 11..14 for completed audits with findings; 1..3 are operational errors.
    valid_findings = _records_have_fields(findings, ("ident",)) and all(
        isinstance(item.get("determinations"), dict)
        and isinstance(item["determinations"].get("severity"), str)
        and _records_have_fields(item.get("locations", []), ())
        for item in findings
    )
    if (result.returncode not in (0, 11, 12, 13, 14) or not valid_findings
            or (result.returncode != 0 and not findings)):
        gate.fail(f"zizmor did not complete (exit {result.returncode})")
    else:
        for finding in findings:
            ident = finding.get("ident", "?")
            if not accepted.covers("zizmor", ident):
                locations = finding.get("locations") or [{}]
                where = locations[0].get("symbolic", {}).get("key", {}).get("Local", {}).get("given_path", "?")
                gate.fail(f"zizmor {ident} ({finding.get('determinations', {}).get('severity', '?')}) in {where}")
    gate.note("actionlint and zizmor (medium and above) over .github/workflows")
    return gate


def gate_dast(out: Path, src: Path, accepted: Accepted, log: Path) -> Gate:
    """Authenticated active scan against a throwaway stack; never point this at shared homologation."""
    gate = Gate("dast")
    project = "openems-dast-" + secrets.token_hex(3)
    admin_password = secrets.token_urlsafe(18)
    env = {**os.environ, "DAST_POSTGRES_PASSWORD": secrets.token_urlsafe(24),
           "DAST_ADMIN_PASSWORD": admin_password, "DAST_SESSION_SECRET": secrets.token_urlsafe(48),
           "DAST_ENROLLMENT_TOKEN": secrets.token_urlsafe(48)}
    compose = ["docker", "compose", "-p", project, "-f", str(ROOT / "docker-compose.dast.yml")]
    try:
        up = run([*compose, "up", "-d", "--build", "--wait", "--wait-timeout", "300"], log=log, env=env, timeout=3600)
        if up.returncode != 0:
            gate.fail("disposable DAST stack did not become healthy; see " + log.name)
            return gate
        schema = run([*compose, "exec", "-T", "server", "python", "-c",
                      "import json; from app.api import create_app; print(json.dumps(create_app(lab_mode=True).openapi()))"],
                     log=log, env=env)
        (out / "openapi.json").write_text(schema.stdout, encoding="utf-8")
        login = run([*compose, "exec", "-T", "-e", "DAST_LOGIN=" + admin_password, "server", "python", "-c",
                     "import json, os, urllib.request; request = urllib.request.Request('http://127.0.0.1:8013/api/v1/auth/login', "
                     "data=json.dumps({'username': 'dastadmin', 'password': os.environ['DAST_LOGIN']}).encode(), "
                     "headers={'Content-Type': 'application/json'}); print(json.load(urllib.request.urlopen(request))['token'])"],
                    log=log, env=env)
        token = login.stdout.strip()
        if login.returncode != 0 or not token:
            gate.fail("could not obtain an administrator token from the disposable stack")
            return gate
        network = project + "_dast"
        docker(IMAGES["zap"], ["zap-baseline.py", "-t", "http://server:8013/panel/", "-J", "zap-baseline.json",
                               "-r", "zap-baseline.html", "-I", "-m", "3"], volumes={out: "/zap/wrk:rw"}, log=log,
               network=network, user_root=True, timeout=1800)
        auth = ("-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true "
                "-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization "
                "-config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer " + token)
        docker(IMAGES["zap"], ["zap-api-scan.py", "-t", "/zap/wrk/openapi.json", "-f", "openapi", "-O", "http://server:8013",
                               "-J", "zap-api.json", "-r", "zap-api.html", "-I", "-z", auth], volumes={out: "/zap/wrk:rw"},
               log=log, network=network, user_root=True, timeout=3600)
        logs = run([*compose, "logs", "server"], log=log, env=env)
        crashes = logs.stdout.count("Traceback") + logs.stdout.count("Exception in ASGI")
        if crashes:
            gate.fail(f"server raised {crashes} unhandled exception(s) under attack")
        for name in ("zap-baseline.json", "zap-api.json"):
            report = load_json(out / name)
            if not isinstance(report, dict):
                gate.fail(f"{name} missing: ZAP did not complete")
                continue
            for site in report.get("site", []):
                for alert in site.get("alerts", []):
                    risk = int(alert.get("riskcode", 0))
                    if risk >= 1 and not accepted.covers("zap", alert["pluginid"]):
                        gate.fail(f"{name}: {alert['pluginid']} {alert['name']} ({alert['riskdesc']})")
        gate.note("ZAP baseline (passive) and authenticated OpenAPI active scan; Low and above block unless accepted")
    finally:
        run([*compose, "down", "-v", "--remove-orphans"], log=log, env=env, timeout=600)
        (out / "zap-token.txt").unlink(missing_ok=True)
    return gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", help="comma-separated gates: " + ",".join(GATES))
    parser.add_argument("--dast", action="store_true", help="also run the DAST gate")
    parser.add_argument("--no-cargo-deny", action="store_true", help="skip cargo-deny (CI runs its pinned action)")
    parser.add_argument("--output", type=Path, help="report directory")
    args = parser.parse_args(argv)
    selected = args.only.split(",") if args.only else [*DEFAULT_GATES, *(["dast"] if args.dast else [])]
    unknown = sorted(set(selected) - set(GATES))
    if unknown:
        parser.error("unknown gate(s): " + ", ".join(unknown))
    out = (args.output or ROOT / ".venv" / "security-reports" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    log = out / "scan.log"
    accepted = Accepted(ROOT / "security" / "accepted-findings.json", datetime.now(UTC).date())
    src = snapshot(out)
    runners: dict[str, Callable[[], Gate]] = {
        "secrets": lambda: gate_secrets(out, accepted, log),
        "sast": lambda: gate_sast(out, src, accepted, log),
        "dependencies": lambda: gate_dependencies(out, src, accepted, log, cargo_deny=not args.no_cargo_deny),
        "container": lambda: gate_container(out, src, accepted, log),
        "workflows": lambda: gate_workflows(out, src, accepted, log),
        "dast": lambda: gate_dast(out, src, accepted, log),
    }
    results = []
    for name in selected:
        started = time.monotonic()
        try:
            gate = runners[name]()
        except (OSError, RuntimeError, subprocess.SubprocessError, KeyError, ValueError) as error:
            gate = Gate(name)
            gate.fail(f"{type(error).__name__}: {error}")
        gate.note(f"{time.monotonic() - started:.0f}s")
        results.append(gate)
        print(f"[{'PASS' if gate.passed else 'FAIL'}] {name}")
        for detail in gate.details:
            print("    " + detail)
    expired = Gate("accepted-findings")
    for item in accepted.expired:
        expired.fail(f"expired exception {item['tool']}:{item['id']} ({item['expires']}): review it again")
    results.append(expired)
    summary = {"finished_at": datetime.now(UTC).isoformat(), "output": str(out),
               "gates": [{"name": g.name, "passed": g.passed, "details": g.details} for g in results]}
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    shutil.rmtree(src, ignore_errors=True)
    failed = [g.name for g in results if not g.passed]
    print(f"reports: {out}")
    print("security gates: " + ("PASSED" if not failed else "FAILED (" + ", ".join(failed) + ")"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
