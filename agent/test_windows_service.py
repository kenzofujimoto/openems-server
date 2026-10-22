"""Service lifecycle and installer checks without changing Windows services."""

import json
from pathlib import Path
import shutil
import subprocess
import threading

import pytest

import service


def write_config(tmp_path, **overrides):
    values = {"server": "https://ems.test", "devid": "device-01"}
    values.update(overrides)
    path = tmp_path / "agent.json"
    path.write_text(json.dumps(values), encoding="utf-8-sig")
    return str(path)


def test_load_config_accepts_existing_bom_and_durable_credentials(tmp_path):
    path = write_config(
        tmp_path, device_token="secret", invitation="invite", state_path="cache.json"
    )
    cfg = service.load_config(path)
    assert cfg.device_token == "secret"
    assert cfg.invitation == "invite"
    assert cfg.state_path == "cache.json"


@pytest.mark.parametrize("field,value", [
    ("block_page", "false"), ("interval", True), ("interval", 0),
    ("block_page_port", 65536), ("devid", 1), ("unknown_option", True),
    ("server", "file:///secret"), ("allow_insecure_http", "false"),
])
def test_load_config_rejects_invalid_options(tmp_path, field, value):
    with pytest.raises(ValueError):
        service.load_config(write_config(tmp_path, **{field: value}))


def test_run_loop_uses_shared_agent_runtime(monkeypatch):
    cfg = object()
    stop = threading.Event()
    calls = []
    monkeypatch.setattr(service, "load_config", lambda: cfg)
    monkeypatch.setattr(service.agent, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    service.run_loop(stop)
    assert calls == [((cfg,), {"log": service.log, "stop_event": stop})]


def test_config_failure_reaches_service_supervisor(monkeypatch):
    def fail():
        raise ValueError("invalid configuration")
    monkeypatch.setattr(service, "load_config", fail)
    with pytest.raises(ValueError, match="invalid configuration"):
        service.run_loop(threading.Event())


def test_worker_failure_wakes_supervisor_and_reports_failure(monkeypatch):
    stopped = threading.Event()
    wake = threading.Event()
    def fail(stop):
        raise ValueError("worker failed")
    monkeypatch.setattr(service, "run_loop", fail)
    with pytest.raises(RuntimeError, match="worker failed"):
        service.supervise(stopped, lambda: wake.wait(2), wake.set)
    assert stopped.is_set()
    assert wake.is_set()


def test_unexpected_worker_return_is_failure(monkeypatch):
    wake = threading.Event()
    monkeypatch.setattr(service, "run_loop", lambda stop: None)
    with pytest.raises(RuntimeError, match="unexpectedly"):
        service.supervise(threading.Event(), lambda: wake.wait(2), wake.set)


def test_log_failure_is_visible_without_disclosing_message(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "LOG_PATH", str(tmp_path / "missing" / "agent.log"))
    monkeypatch.setattr(service, "_make_log_handler", lambda: (_ for _ in ()).throw(OSError("no access")), raising=False)
    service.log("sensitive payload")
    captured = capsys.readouterr()
    assert "log unavailable" in captured.err.lower()
    assert "sensitive payload" not in captured.err


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is unavailable")
def test_installer_native_failures_are_fatal_and_script_parses():
    path = Path(service.__file__).with_name("install_service.ps1")
    # Only load one function AST; never execute the installation body.
    script = r'''
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$errors)
    if ($errors.Count) { throw "PowerShell parse error" }
    $function = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-CheckedNative'}, $true)
    if ($null -eq $function) { throw "Missing native exit guard" }
    Invoke-Expression $function.Extent.Text
    try { Invoke-CheckedNative -FilePath $args[1] -Arguments @('-NoProfile', '-Command', 'exit 9'); throw 'Failure was ignored' }
    catch { if ($_.Exception.Message -notmatch 'exit code 9') { throw } }
    '''
    result = subprocess.run(
        [shutil.which("pwsh"), "-NoProfile", "-Command", "& {" + script + "}", str(path), shutil.which("pwsh")],
        text=True, capture_output=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
