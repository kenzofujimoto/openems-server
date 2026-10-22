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
        finally:
            removed = run_agent(native, "uninstall-service", "--config", str(config), invitation=None)
        assert removed.returncode == 0, removed.stderr
        assert "1060" in _query("openems-agent") or "does not exist" in _query("openems-agent").lower()
        assert hosts.read_bytes() == b"# service checkpoint\r\n"
