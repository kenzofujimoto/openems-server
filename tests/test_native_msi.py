"""Install and remove the MSI on a disposable CI Windows runner.

Requires Administrator rights, OPENEMS_SERVICE_TESTS=1 and OPENEMS_MSI pointing
to a built openems-agent.msi. It writes ProgramData\\openems and a temporary
hosts file only; the system hosts file is never touched.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION, detail, publish

pytestmark = [
    pytest.mark.windows_only,
    pytest.mark.skipif(
        os.name != "nt" or os.environ.get("OPENEMS_SERVICE_TESTS") != "1" or not os.environ.get("OPENEMS_MSI"),
        reason="MSI installation runs only on CI Windows runners",
    ),
]

DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "openems"
INSTALL_DIR = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "openems"


def msiexec(*args: str, log: Path) -> int:
    return subprocess.run(["msiexec.exe", *args, "/qn", "/norestart", "/l*v", str(log)], check=False).returncode


def failure_context(log: Path) -> str:
    """msiexec writes UTF-16 logs; show the lines around the first failing action."""
    try:
        lines = log.read_text(encoding="utf-16", errors="replace").splitlines()
    except OSError:
        return "msiexec log unavailable"
    failed = next((index for index, line in enumerate(lines) if "Return value 3" in line), len(lines) - 1)
    return "\n".join(lines[max(0, failed - 40):failed + 5])


def sc(*args: str) -> str:
    return subprocess.run(["sc.exe", *args], capture_output=True, text=True, check=False).stdout


def test_msi_installs_a_recovering_service_without_python_and_uninstalls_cleanly(tmp_path):
    assert ctypes.windll.shell32.IsUserAnAdmin(), "MSI tests need Administrator rights"
    msi = Path(os.environ["OPENEMS_MSI"]).resolve()
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# msi checkpoint\r\n")
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    with live_server() as (_, origin, client):
        publish(client)
        assert msiexec("/i", str(msi), f"SERVER={origin}", f"INVITATION={INVITATION}", "DEVID=msi-pc",
                       f"HOSTSFILE={hosts}", log=tmp_path / "install.log") == 0, failure_context(tmp_path / "install.log")
        try:
            assert (INSTALL_DIR / "openems-agent.exe").is_file()
            assert not list(INSTALL_DIR.glob("*.py")), "the native install ships no Python code"
            assert "AUTO_START" in sc("qc", "openems-agent")
            assert "RESTART" in sc("qfailure", "openems-agent").upper()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if detail(client, "msi-pc")["applied_vdom"] == "Default":
                    break
                time.sleep(1)
            else:
                pytest.fail("installed service did not apply the policy in time")
            assert "0.0.0.0 example.com" in hosts.read_bytes().decode("utf-8")
            config = (DATA_DIR / "agent.json").read_text(encoding="utf-8")
            assert origin in config
            # Kill the process: the configured recovery must bring the service back.
            subprocess.run(["taskkill.exe", "/f", "/im", "openems-agent.exe"], capture_output=True, check=False)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and "RUNNING" not in sc("query", "openems-agent"):
                time.sleep(1)
            assert "RUNNING" in sc("query", "openems-agent"), "service was not restarted after a crash"
        finally:
            removed = msiexec("/x", str(msi), log=tmp_path / "uninstall.log")
        assert removed == 0, failure_context(tmp_path / "uninstall.log")
        assert "1060" in sc("query", "openems-agent")
        assert not (INSTALL_DIR / "openems-agent.exe").exists()
        assert hosts.read_bytes() == b"# msi checkpoint\r\n"
