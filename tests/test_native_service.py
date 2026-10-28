"""Install the native agent as a real Windows service (CI Windows runners only).

Requires Administrator rights. Enabled with OPENEMS_SERVICE_TESTS=1 so that
developer machines never register services by accident.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
import uuid

import pytest

from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION, detail, publish, run_agent

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(os.name != "nt" or os.environ.get("OPENEMS_SERVICE_TESTS") != "1",
                       reason="real service installation runs only on CI Windows runners"),
]


def _query(name: str) -> str:
    return subprocess.run(["sc.exe", "query", name], capture_output=True, text=True, check=False).stdout


def run_as_system(binary, *arguments: str, timeout: float = 180) -> int:
    """Run the agent as SYSTEM through a one-off scheduled task and return its exit code."""
    task = "openems-ci-" + uuid.uuid4().hex
    quoted = subprocess.list2cmdline([str(argument) for argument in arguments]).replace("'", "''")
    executable = str(binary).replace("'", "''")
    register = (f"$action = New-ScheduledTaskAction -Execute '{executable}' -Argument '{quoted}'; "
                f"Register-ScheduledTask -TaskName '{task}' -Action $action -User SYSTEM -RunLevel Highest | Out-Null; "
                f"Start-ScheduledTask -TaskName '{task}'")
    powershell = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]
    subprocess.run([*powershell, register], capture_output=True, text=True, timeout=60, check=True)
    try:
        deadline = time.monotonic() + timeout
        # 267009 = task is running, 267011 = task has not run yet.
        while time.monotonic() < deadline:
            info = subprocess.run([*powershell, f"(Get-ScheduledTaskInfo -TaskName '{task}').LastTaskResult"],
                                  capture_output=True, text=True, timeout=60, check=True).stdout.strip()
            if info and int(info) not in (267009, 267011):
                return int(info)
            time.sleep(1)
        raise AssertionError(f"SYSTEM task {task} did not finish in {timeout} s")
    finally:
        subprocess.run([*powershell, f"Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false"],
                       capture_output=True, text=True, timeout=60, check=False)


def test_service_installs_enforces_restarts_on_failure_and_uninstalls(native, tmp_path):
    assert ctypes.windll.shell32.IsUserAnAdmin(), "service tests need Administrator rights"
    config = tmp_path / "agent.json"
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# service checkpoint\r\n")
    with live_server() as (_, origin, client):
        publish(client)
        configured = run_agent(native, "configure", "--config-path", str(config), "--server", origin, "--devid", "service-pc",
                               "--invitation", INVITATION, "--hosts-file", str(hosts), "--state-path", str(tmp_path / "state.json"),
                               "--interval", "2", invitation=None)
        assert configured.returncode == 0, configured.stderr
        installed = run_agent(native, "install-service", "--config", str(config), "--start", invitation=None)
        assert installed.returncode == 0, installed.stderr
        try:
            failure = subprocess.run(["sc.exe", "qfailure", "openems-agent"], capture_output=True, text=True, check=False).stdout
            assert "RESTART" in failure.upper()
            assert "AUTO_START" in subprocess.run(["sc.exe", "qc", "openems-agent"], capture_output=True, text=True, check=False).stdout
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if "RUNNING" in _query("openems-agent") and detail(client, "service-pc")["applied_vdom"] == "Default":
                    break
                time.sleep(1)
            else:
                pytest.fail("service did not apply the policy in time")
            assert "0.0.0.0 example.com" in hosts.read_bytes().decode("utf-8")
            assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["client_id"]
            # Tamper protection: the service DACL denies stop/delete to Administrators, so an elevated
            # admin cannot remove it; only SYSTEM (the MSI path) can.
            refused = run_agent(native, "uninstall-service", "--config", str(config), invitation=None)
            assert refused.returncode != 0, "an elevated administrator removed the protected service"
            assert "RUNNING" in _query("openems-agent")
        finally:
            removed = run_as_system(native, "uninstall-service", "--config", str(config))
        assert removed == 0, f"uninstall-service as SYSTEM exited {removed}"
        assert "1060" in _query("openems-agent") or "does not exist" in _query("openems-agent").lower()
        assert hosts.read_bytes() == b"# service checkpoint\r\n"
