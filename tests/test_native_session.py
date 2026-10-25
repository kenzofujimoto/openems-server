"""Session component (session-component.md): the agent fills session.json and openems-session reads it.

The tray icon and balloons need an interactive session and run in the Sandbox acceptance; here the agent
runs as the current user against a disposable server, and the component runs in its --print mode.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_agent_integration import live_server
from tests.test_native_agent import INVITATION
from tests.test_native_categories import stop, wait_for

APP = "openems-test-app.exe"


def start(native: Path, origin: str, tmp_path: Path) -> subprocess.Popen:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    environment["OPENEMS_INVITATION"] = INVITATION
    (tmp_path / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    return subprocess.Popen(
        [str(native), "run", "--server", origin, "--devid", "session-pc", "--interval", "1",
         "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
    )


def board(tmp_path: Path) -> dict:
    try:
        return json.loads((tmp_path / "session.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, PermissionError, ValueError):
        return {}


def session_binary(native: Path) -> Path:
    binary = native.with_name("openems-session" + native.suffix)
    if not binary.is_file():
        pytest.fail(f"{binary.name} was not built next to {native.name}")
    return binary


@pytest.mark.skipif(os.name != "nt", reason="uses a copy of PING.EXE as the blocked application")
def test_a_closed_application_reaches_the_session_board(native, tmp_path):
    dummy = tmp_path / APP
    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "PING.EXE", dummy)
    with live_server() as (_, origin, client):
        response = client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": []},
                                                                 "app_control": {"blocked": [APP]}})
        assert response.status_code == 200
        agent = start(native, origin, tmp_path)
        victim = None
        try:
            assert wait_for(lambda: board(tmp_path).get("protected") is True, 30), stop(agent)
            victim = subprocess.Popen([str(dummy), "-n", "120", "127.0.0.1"], stdout=subprocess.DEVNULL)
            closed = lambda: any(APP in notice["text"].lower() for notice in board(tmp_path).get("notices", []))  # noqa: E731
            if not wait_for(closed, 30):
                raise AssertionError(f"no notice: {board(tmp_path)}\n" + stop(agent))
            assert victim.wait(timeout=10) is not None, "the application was closed"
            state = board(tmp_path)
            assert state["last_contact"], "a successful synchronization is recorded"
            [notice] = [notice for notice in state["notices"] if APP in notice["text"].lower()]
            assert notice["kind"] == "app_closed" and notice["text"].endswith("foi fechado pela política da empresa.")
        finally:
            if victim is not None and victim.poll() is None:
                victim.kill()
            if agent.poll() is None:
                stop(agent)


def test_the_session_component_prints_what_it_would_show(native, tmp_path):
    path = tmp_path / "session.json"
    path.write_text(json.dumps({"protected": True, "last_contact": None, "notices": [
        {"id": 7, "at": "2000-01-01T00:00:00Z", "kind": "app_closed", "text": "old.exe foi fechado pela política da empresa."},
    ]}), encoding="utf-8")
    result = subprocess.run([str(session_binary(native)), "--print", "--board", str(path)],
                            capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    shown = json.loads(result.stdout)
    assert shown == {"tooltip": "RSM Endpoint: proteção ativa, sem contato com o servidor", "notices": []}
    missing = subprocess.run([str(session_binary(native)), "--print", "--board", str(tmp_path / "absent.json")],
                             capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    assert json.loads(missing.stdout) == {"tooltip": "RSM Endpoint: aguardando a política da empresa", "notices": []}
