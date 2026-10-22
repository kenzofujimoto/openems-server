"""Service lifecycle and installer checks without changing Windows services."""

import importlib.util
import json
import os
import runpy
import shutil
import subprocess
import sys
import threading
import traceback
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import blockpage
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


@pytest.mark.parametrize("payload", [[], {"devid": "device-01"}])
def test_load_config_rejects_missing_required_configuration(tmp_path, payload):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        service.load_config(str(path))


def test_run_loop_uses_shared_agent_runtime(monkeypatch):
    cfg = object()
    stop = threading.Event()
    stop.set()  # Also bounds the legacy loop during the red phase.
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


def run_pwsh(tmp_path: Path, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run a harness from a script file; -Command would split arguments on spaces."""
    harness_dir = tmp_path / "harness"
    harness_dir.mkdir(exist_ok=True)
    harness = harness_dir / "harness.ps1"
    harness.write_text(script, encoding="utf-8-sig")
    # A cold pwsh start on hosted runners can exceed 20 seconds.
    environment = {**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off"}
    return subprocess.run(
        [shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-File", str(harness), *arguments],
        text=True, capture_output=True, timeout=90, check=False, env=environment,
    )


def test_log_failure_is_visible_without_disclosing_message(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(service, "HAVE_PYWIN32", False)
    monkeypatch.setattr(service, "LOG_PATH", str(tmp_path / "missing" / "agent.log"))
    monkeypatch.setattr(service, "_make_log_handler", lambda: (_ for _ in ()).throw(OSError("no access")), raising=False)
    service.log("sensitive payload")
    captured = capsys.readouterr()
    assert "log unavailable" in captured.err.lower()
    assert "sensitive payload" not in captured.err


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is unavailable")
@pytest.mark.parametrize("script_name", ["install_service.ps1", "uninstall_service.ps1"])
def test_installer_native_failures_are_fatal_and_script_parses(script_name, tmp_path):
    path = Path(service.__file__).with_name(script_name)
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
    result = run_pwsh(tmp_path, script, str(path), shutil.which("pwsh"))
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows PowerShell harness")
@pytest.mark.windows_only
def test_install_start_failure_rolls_back_service_and_keeps_protected_data(tmp_path):
    path = Path(service.__file__).with_name("install_service.ps1")
    script = r'''
    $script:installSource = $args[0]
    $env:ProgramData = $args[1]
    $script:calls = [Collections.Generic.List[string]]::new()
    $script:serviceExists = $false
    $source = [IO.File]::ReadAllText($script:installSource)
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$errors)
    if ($errors.Count) { throw 'Invalid PowerShell syntax' }
    $functions = $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $true)
    foreach ($f in ($functions | Sort-Object {$_.Extent.StartOffset} -Descending)) {
        $source = $source.Remove($f.Extent.StartOffset, $f.Extent.EndOffset - $f.Extent.StartOffset)
    }
    $source = $source.Replace('#Requires -RunAsAdministrator', '').Replace('$MyInvocation.MyCommand.Path', '$script:installSource')
    function Assert-ProtectedPath { param($Path) }
    function Resolve-Path { param($LiteralPath) [PSCustomObject]@{ ProviderPath = 'C:\openems-test-runtime\python.exe' } }
    function Set-Acl { param($LiteralPath, $AclObject) $script:calls.Add('protected-acl') }
    function Get-Service {
        param($Name, $ErrorAction)
        if ($script:serviceExists) { [PSCustomObject]@{ Status = 'Stopped' } }
    }
    function Wait-ManagedService { param($Status) $script:calls.Add("wait-$Status") }
    function Invoke-CheckedNative {
        param($FilePath, [string[]]$Arguments)
        $script:calls.Add(($Arguments -join ' '))
        if ($Arguments -contains 'install') { $script:serviceExists = $true }
        if ($Arguments -contains 'start') { throw 'mocked start failure' }
        if ($Arguments -contains 'remove') { $script:serviceExists = $false }
    }
    try { & ([ScriptBlock]::Create($source)) -PythonPath $args[2]; throw 'Expected installation failure' }
    catch { if ($_.Exception.Message -notmatch 'mocked start failure') { throw } }
    $cfg = Join-Path $env:ProgramData 'openems\agent.json'
    if ($script:serviceExists) { throw 'Service rollback did not remove created service' }
    if (-not (Test-Path -LiteralPath $cfg)) { throw 'Protected config was deleted' }
    $bytes = [IO.File]::ReadAllBytes($cfg)
    if ($bytes[0] -eq 239) { throw 'Configuration has a UTF8 BOM' }
    if (-not ($script:calls | Where-Object {$_ -match 'cleanup-hosts$'})) { throw 'Managed hosts rollback missing' }
    if ($script:calls[0] -ne '-I -c import sys; assert sys.version_info >= (3, 11); assert sys.prefix == sys.base_prefix, "A global Python installation is required"') { throw 'Runtime validation did not precede installation' }
    '''
    result = run_pwsh(tmp_path, script, str(path), str(tmp_path), "unused-runtime")
    assert result.returncode == 0, result.stderr


def load_service_with_fake_scm(monkeypatch):
    statuses = []
    messages = []
    signals = []

    class Framework:
        def __init__(self, args):
            pass

        def ReportServiceStatus(self, status, **kwargs):
            statuses.append((status, kwargs))

    modules = {
        "win32serviceutil": SimpleNamespace(ServiceFramework=Framework),
        "win32service": SimpleNamespace(SERVICE_STOP_PENDING=3, SERVICE_STOPPED=1),
        "win32event": SimpleNamespace(
            CreateEvent=lambda *args: "wait-handle", SetEvent=lambda handle: signals.append(handle),
            WaitForSingleObject=lambda handle, timeout: None, INFINITE=-1,
        ),
        "servicemanager": SimpleNamespace(LogErrorMsg=messages.append),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location("isolated_openems_service", service.__file__)
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)
    monkeypatch.setattr(isolated, "log", messages.append)
    return isolated, statuses, messages, signals


def test_scm_stop_wakes_worker_and_failed_worker_sets_nonzero_exit(monkeypatch):
    isolated, statuses, messages, signals = load_service_with_fake_scm(monkeypatch)
    instance = isolated.OpenemsAgentService([])
    instance.SvcStop()
    assert instance._stop.is_set()
    assert statuses == [(3, {})]
    assert signals == ["wait-handle"]

    def fail(*args):
        raise ValueError("credential-secret-must-not-be-logged")
    monkeypatch.setattr(isolated, "supervise", fail)
    with pytest.raises(RuntimeError) as failure:
        instance.SvcDoRun()
    assert statuses[-1] == (1, {"win32ExitCode": 1066, "svcExitCode": 1})
    assert messages
    assert all("credential-secret" not in message for message in messages)
    assert "credential-secret" not in "".join(traceback.format_exception(failure.value))


def test_scm_run_wires_wait_and_wake_callbacks(monkeypatch):
    isolated, _, messages, signals = load_service_with_fake_scm(monkeypatch)
    instance = isolated.OpenemsAgentService([])
    calls = []
    def supervise(stop, wait, wake):
        calls.append(stop)
        wait()
        wake()
    monkeypatch.setattr(isolated, "supervise", supervise)
    instance.SvcDoRun()
    assert calls == [instance._stop]
    assert signals == ["wait-handle"]
    assert messages == []


def test_block_page_only_listens_on_loopback_and_bind_errors_are_synchronous():
    with blockpage.create_server(0) as listener:
        assert listener.server_address[0] == "127.0.0.1"
        with pytest.raises(OSError):
            blockpage.create_server(listener.server_address[1])


def test_service_log_rotates_and_preserves_recent_messages(tmp_path, monkeypatch):
    path = tmp_path / "agent.log"
    monkeypatch.setattr(service, "LOG_PATH", str(path))
    service.log("x" * (2 * 1024 * 1024))
    service.log("recent event")
    assert "recent event" in path.read_text(encoding="utf-8")
    assert path.with_name("agent.log.1").exists()


def test_cleanup_command_only_removes_managed_hosts_block(tmp_path, monkeypatch):
    config_dir = tmp_path / "openems"
    config_dir.mkdir()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n" + service.agent.render_hosts_block(["example.com"]), encoding="utf-8")
    (config_dir / "agent.json").write_text(json.dumps({
        "server": "https://ems.test", "devid": "device-01", "hosts_path": str(hosts),
    }), encoding="utf-8")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    monkeypatch.setattr(sys, "argv", [service.__file__, "cleanup-hosts"])
    runpy.run_path(service.__file__, run_name="__main__")
    assert hosts.read_text(encoding="utf-8") == "127.0.0.1 localhost\n"


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_local_block_page_serves_http_and_escapes_host_header(method):
    with blockpage.create_server(0) as listener:
        worker = threading.Thread(target=listener.serve_forever, daemon=True)
        worker.start()
        try:
            address = f"http://127.0.0.1:{listener.server_address[1]}/blocked/path"
            request = urllib.request.Request(address, headers={"Host": "<script>alert(1)</script>.test"}, method=method)
            with urllib.request.urlopen(request, timeout=3) as response:
                body = response.read().decode("utf-8")
                assert response.status == 200
                assert response.headers["Cache-Control"] == "no-store"
                assert response.headers["Content-Type"] == "text/html; charset=utf-8"
                assert "&lt;script&gt;" in body
                assert "<script>" not in body
        finally:
            listener.shutdown()
            worker.join(timeout=3)
        assert not worker.is_alive()


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows ACL API harness")
@pytest.mark.parametrize("script_name", ["install_service.ps1", "uninstall_service.ps1"])
def test_python_acl_accepts_read_only_users_and_rejects_untrusted_writes(script_name, tmp_path):
    path = Path(service.__file__).with_name(script_name)
    script = r'''
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$errors)
    $function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ProtectedPath'}, $true)
    Invoke-Expression $function.Extent.Text
    function Get-Item { param($LiteralPath, $ErrorAction) [PSCustomObject]@{Attributes = [IO.FileAttributes]::Normal} }
    $script:access = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $script:owner = 'S-1-5-32-544'
    function Get-Acl {
        param($LiteralPath)
        $result = [PSCustomObject]@{Access = @([PSCustomObject]@{
            IdentityReference = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
            AccessControlType = 'Allow'; FileSystemRights = $script:access
        })}
        $result | Add-Member ScriptMethod GetOwner { param($target) [Security.Principal.SecurityIdentifier]::new($script:owner) }
        return $result
    }
    Assert-ProtectedPath 'fake-path'
    $script:access = [Security.AccessControl.FileSystemRights]::Modify
    try { Assert-ProtectedPath 'fake-path'; throw 'Untrusted writes were accepted' }
    catch { if ($_.Exception.Message -notmatch 'only be writable') { throw } }
    $script:access = [Security.AccessControl.FileSystemRights]::ReadAndExecute
    $script:owner = 'S-1-5-21-1-2-3-1001'
    try { Assert-ProtectedPath 'fake-path'; throw 'Untrusted ownership was accepted' }
    catch { if ($_.Exception.Message -notmatch 'owned by') { throw } }
    '''
    result = run_pwsh(tmp_path, script, str(path))
    assert result.returncode == 0, result.stderr
