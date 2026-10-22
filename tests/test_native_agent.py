"""Contract tests for the native (Rust) endpoint agent against a real server.

They exercise the compiled binary exactly as the Windows service will, using
only disposable hosts and state files. Set OPENEMS_NATIVE_AGENT to a binary;
otherwise agent-rs/target/{release,debug}/openems-agent is used. CI sets
OPENEMS_REQUIRE_NATIVE_AGENT=1 so a missing binary fails instead of skipping.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.test_agent_integration import live_server

ROOT = Path(__file__).resolve().parent.parent
INVITATION = "e2e-invitation"


def run_agent(binary: Path, *args: str, invitation: str | None = INVITATION) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENEMS_")}
    if invitation:
        environment["OPENEMS_INVITATION"] = invitation
    return subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=60, env=environment, check=False)


def once(binary: Path, origin: str, tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return run_agent(
        binary, "run-once", "--server", origin, "--devid", "native-pc",
        "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json"), *extra,
    )


def detail(client, devid: str = "native-pc") -> dict:
    response = client.get("/api/v1/endpoints/detail", params={"devid": devid})
    assert response.status_code == 200
    return response.json()


def publish(client) -> None:
    for group, domain in (("Default", "example.com"), ("Strict", "strict.test")):
        response = client.post(f"/api/v1/profiles/{group}", json={"web_filter": {"blocked": [domain]}, "app_control": {"blocked": []}})
        assert response.status_code == 200


def test_reports_its_version(native):
    result = run_agent(native, "--version", invitation=None)
    assert result.returncode == 0
    assert result.stdout.startswith("openems-agent ")


def test_enrolls_enforces_acknowledges_and_preserves_foreign_entries(native, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"127.0.0.1 localhost\r\n10.0.0.5 intranet.local\r\n")
    with live_server() as (_, origin, client):
        publish(client)
        result = once(native, origin, tmp_path)
        assert result.returncode == 0, result.stderr
        text = hosts.read_bytes().decode("utf-8")  # read_text() would hide CRLF
        assert "0.0.0.0 example.com" in text and "0.0.0.0 www.example.com" in text
        assert text.startswith("127.0.0.1 localhost\r\n10.0.0.5 intranet.local\r\n")
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        info = detail(client)
        assert info["config_version"] == 1 and info["applied_vdom"] == "Default"
        assert info["applied_digest"] == info["desired_profile"]["digest"] and info["last_error"] == ""
        assert "vdom:Default" in info["host_tags"]
        assert state["device_token"] not in result.stdout + result.stderr


def test_follows_group_moves_and_explicit_release(native, tmp_path):
    with live_server() as (_, origin, client):
        publish(client)
        assert once(native, origin, tmp_path).returncode == 0
        client.post("/api/v1/assignment_rules", json={"id": "move", "target_vdom": "Strict", "priority": 0, "conditions": []}).raise_for_status()
        assert once(native, origin, tmp_path).returncode == 0
        text = (tmp_path / "hosts").read_text(encoding="utf-8")
        assert "strict.test" in text and "example.com" not in text
        assert detail(client)["applied_vdom"] == "Strict"
        client.post("/api/v1/assignment_rules", json={"id": "move", "target_vdom": "Empty", "priority": 0, "conditions": []}).raise_for_status()
        assert once(native, origin, tmp_path).returncode == 0
        assert "openems managed block" not in (tmp_path / "hosts").read_text(encoding="utf-8")
        info = detail(client)
        assert info["applied_vdom"] == "Empty" and info["config_version"] == 0 and info["desired_profile"] is None


def test_keeps_identity_and_cached_policy_when_the_server_is_gone(native, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# checkpoint\n")
    with live_server() as (_, origin, client):
        publish(client)
        assert once(native, origin, tmp_path).returncode == 0
        identity = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["client_id"]
    hosts.write_bytes(b"# checkpoint\n")  # someone removed the block while offline
    offline = once(native, origin, tmp_path)
    assert offline.returncode == 0, offline.stderr
    assert "synchronization failed" in offline.stderr
    assert "0.0.0.0 example.com" in hosts.read_text(encoding="utf-8")
    assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["client_id"] == identity
    cleanup = run_agent(native, "cleanup-hosts", "--hosts-file", str(hosts), invitation=None)
    assert cleanup.returncode == 0, cleanup.stderr
    assert hosts.read_bytes() == b"# checkpoint\n"


def test_refuses_a_tampered_cached_policy_without_touching_hosts(native, tmp_path):
    with live_server() as (_, origin, client):
        publish(client)
        assert once(native, origin, tmp_path).returncode == 0
        state_path = tmp_path / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["profile"]["body"]["web_filter"]["blocked"] = ["attacker.example"]
        state_path.write_text(json.dumps(state), encoding="utf-8")
        before = (tmp_path / "hosts").read_bytes()
        result = once(native, origin, tmp_path)
        assert result.returncode != 0
        assert "state" in result.stderr.lower()
        assert (tmp_path / "hosts").read_bytes() == before


def test_reads_service_configuration_with_a_byte_order_mark(native, tmp_path):
    with live_server() as (_, origin, client):
        publish(client)
        config = tmp_path / "agent.json"
        settings = {"server": origin, "devid": "native-pc", "invitation": INVITATION, "interval": 15,
                    "hosts_path": str(tmp_path / "hosts"), "state_path": str(tmp_path / "state.json")}
        config.write_bytes(b"\xef\xbb\xbf" + json.dumps(settings).encode("utf-8"))
        result = run_agent(native, "run-once", "--config", str(config), invitation=None)
        assert result.returncode == 0, result.stderr
        assert detail(client)["applied_vdom"] == "Default"
        settings["unknown_option"] = True
        config.write_text(json.dumps(settings), encoding="utf-8")
        rejected = run_agent(native, "run-once", "--config", str(config), invitation=None)
        assert rejected.returncode != 0 and "configuration" in rejected.stderr.lower()


def test_takes_over_python_agent_state_without_re_enrolling(native, tmp_path):
    sys.path.insert(0, str(ROOT / "agent"))
    import openems_agent as python_agent

    with live_server() as (service, origin, client):
        publish(client)
        config = python_agent.AgentConfig(server=origin, devid="native-pc", invitation=INVITATION,
                                          hosts_path=str(tmp_path / "hosts"), state_path=str(tmp_path / "state.json"))
        python_agent.AgentRuntime(config, log=lambda message: None).cycle(now=0)
        identity = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["client_id"]
        # No invitation: re-enrolling would fail, so success proves the identity was reused.
        result = run_agent(
            native, "run-once", "--server", origin, "--devid", "native-pc",
            "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json"), invitation=None,
        )
        assert result.returncode == 0, result.stderr
        assert service.count() == 1
        assert json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))["client_id"] == identity


def test_rejects_plain_http_to_remote_servers(native, tmp_path):
    result = once(native, "http://ems.example.com", tmp_path)
    assert result.returncode != 0
    assert "https" in result.stderr.lower()


def test_configure_writes_a_strict_service_configuration(native, tmp_path):
    config = tmp_path / "openems" / "agent.json"
    with live_server() as (_, origin, client):
        publish(client)
        written = run_agent(
            native, "configure", "--config-path", str(config), "--server", origin, "--devid", "native-pc",
            "--invitation", INVITATION, "--hosts-file", str(tmp_path / "hosts"), "--state-path", str(tmp_path / "state.json"),
            invitation=None,
        )
        assert written.returncode == 0, written.stderr
        settings = json.loads(config.read_text(encoding="utf-8"))
        assert settings["server"] == origin and settings["devid"] == "native-pc" and settings["invitation"] == INVITATION
        assert INVITATION not in written.stdout + written.stderr
        assert run_agent(native, "run-once", "--config", str(config), invitation=None).returncode == 0
        assert detail(client)["applied_vdom"] == "Default"
    refused = run_agent(native, "configure", "--config-path", str(config), "--server", "http://ems.example.com",
                        "--devid", "pc", invitation=None)
    assert refused.returncode != 0 and "https" in refused.stderr.lower()
