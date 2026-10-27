"""The DAST gate must prove an authenticated, fresh scan and keep its token out of logs (Codex review)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from tools import security_scan as scanner

TOKEN = "fixture-admin-session-token-0123456789abcdef"


def zap_report(alerts: list[dict] | None = None) -> str:
    return json.dumps({"site": [{"alerts": alerts or []}]})


class DastHarness:
    """Fake only the process boundaries: compose, the login/session probes and the ZAP container."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch):
        self.out = root / "reports"
        self.out.mkdir()
        accepted = root / "accepted.json"
        accepted.write_text('{"findings": []}', encoding="utf-8")
        self.accepted = scanner.Accepted(accepted, date(2026, 10, 27))
        self.session_status = "200"
        self.down_exit = 0
        self.zap_exit = {"zap-baseline.json": 0, "zap-api.json": 0}
        self.zap_writes = {"zap-baseline.json": zap_report(), "zap-api.json": zap_report()}
        self.logged: list[str] = []
        monkeypatch.setattr(scanner, "run", self.run)
        monkeypatch.setattr(scanner, "docker", self.docker)

    def run(self, command: list[str], *, quiet: bool = False, **_kwargs) -> subprocess.CompletedProcess:
        text = " ".join(command)
        stdout = ""
        code = 0
        if " exec " in text and "openapi()" in text:
            stdout = "{}"
        elif " exec " in text and "auth/login" in text:
            stdout = TOKEN + "\n"
        elif " exec " in text and "auth/session" in text:
            stdout = self.session_status + "\n"
        elif text.endswith("down -v --remove-orphans"):
            code = self.down_exit
        if not quiet:
            self.logged.append(stdout)
        return subprocess.CompletedProcess(command, code, stdout, "")

    def docker(self, image: str, args: list[str], **_kwargs) -> subprocess.CompletedProcess:
        assert image == scanner.IMAGES["zap"]
        report = args[args.index("-J") + 1]
        content = self.zap_writes.get(report)
        if content is not None:
            (self.out / report).write_text(content, encoding="utf-8")
        return subprocess.CompletedProcess(["docker"], self.zap_exit[report], "", "")

    def gate(self) -> scanner.Gate:
        return scanner.gate_dast(self.out, self.out, self.accepted, self.out / "scan.log")


@pytest.fixture
def dast(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DastHarness:
    return DastHarness(tmp_path, monkeypatch)


def test_clean_authenticated_scan_passes(dast):
    gate = dast.gate()
    assert gate.passed, gate.details


def test_admin_token_never_reaches_the_log(dast):
    dast.gate()
    assert all(TOKEN not in entry for entry in dast.logged)


def test_token_that_does_not_authenticate_fails_before_scanning(dast):
    dast.session_status = "401"
    gate = dast.gate()
    assert not gate.passed and any("authenticate" in detail for detail in gate.details)


@pytest.mark.parametrize("report", ["zap-baseline.json", "zap-api.json"])
def test_zap_error_exit_fails_even_with_a_report(dast, report):
    dast.zap_exit[report] = 3  # ZAP: 0 pass, 1 FAIL, 2 WARN, 3 other error
    assert not dast.gate().passed


@pytest.mark.parametrize("report", ["zap-baseline.json", "zap-api.json"])
def test_stale_report_is_not_accepted(dast, report):
    (dast.out / report).write_text(zap_report(), encoding="utf-8")
    dast.zap_writes[report] = None
    assert not dast.gate().passed


def test_teardown_failure_fails_the_gate(dast):
    dast.down_exit = 1
    gate = dast.gate()
    assert not gate.passed and any("down" in detail for detail in gate.details)


def test_quiet_run_keeps_stdout_out_of_the_log(tmp_path):
    log = tmp_path / "scan.log"
    original = scanner.run.__wrapped__ if hasattr(scanner.run, "__wrapped__") else scanner.run
    # Like the gate, the secret arrives through the environment, not argv (argv heads are logged).
    environment = {**os.environ, "SCAN_SECRET": TOKEN}
    result = original([sys.executable, "-c", "import os; print(os.environ['SCAN_SECRET'])"], log=log,
                      quiet=True, env=environment)
    assert TOKEN in result.stdout
    assert TOKEN not in log.read_text(encoding="utf-8")
