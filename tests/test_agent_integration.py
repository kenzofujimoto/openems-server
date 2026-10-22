"""Real loopback HTTP integration; only disposable hosts files are modified."""

import socket
import threading
import time
from contextlib import contextmanager

import httpx
import openems_agent as agent
import uvicorn

from app.api import create_app
from app.auth import AdminService
from app.service import EmsService


@contextmanager
def live_server():
    service = EmsService(valid_invitations={"e2e-invitation"})
    admins = AdminService()
    admins.add_admin("operator", "e2e-test-password")
    application = create_app(service, admin_service=admins)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(application, log_level="critical"))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    try:
        for _ in range(500):
            if server.started:
                break
            time.sleep(0.01)
        assert server.started, "Disposable HTTP server failed to start"
        with httpx.Client(base_url=origin, timeout=5, trust_env=False) as client:
            response = client.post("/api/v1/auth/login", json={"username": "operator", "password": "e2e-test-password"})
            assert response.status_code == 200
            client.headers["Authorization"] = "Bearer " + response.json()["token"]
            yield service, origin, client
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        listener.close()
        assert not worker.is_alive(), "Disposable server did not shut down"


def test_agent_enforces_acknowledges_moves_groups_and_recovers_offline(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_bytes(b"# integration checkpoint\r\n")
    state = tmp_path / "state.json"
    with live_server() as (_, origin, client):
        for group, domain in (("Default", "example.com"), ("Strict", "strict.test")):
            response = client.post(f"/api/v1/profiles/{group}", json={"web_filter": {"blocked": [domain]}, "app_control": {"blocked": []}})
            assert response.status_code == 200
        config = agent.AgentConfig(server=origin, devid="integration-pc", invitation="e2e-invitation", hosts_path=str(hosts), state_path=str(state), interval=1)
        runtime = agent.AgentRuntime(config, log=lambda message: None)
        runtime.cycle(now=0)
        assert "0.0.0.0 example.com" in hosts.read_text()
        detail = client.get("/api/v1/endpoints/detail", params={"devid": "integration-pc"}).json()
        assert detail["config_version"] == 1
        assert detail["applied_vdom"] == "Default"
        assert detail["applied_digest"] == detail["desired_profile"]["digest"]
        assert detail["last_error"] == ""
        client.post("/api/v1/assignment_rules", json={"id": "move", "target_vdom": "Strict", "priority": 0, "conditions": []}).raise_for_status()
        runtime.cycle(now=2)
        assert "strict.test" in hosts.read_text() and "example.com" not in hosts.read_text()
        detail = client.get("/api/v1/endpoints/detail", params={"devid": "integration-pc"}).json()
        assert detail["config_version"] == 1 and detail["applied_vdom"] == "Strict"
        known_identity = runtime.client_id
    # The actual listener is closed. Restart with saved credentials and policy.
    hosts.write_bytes(b"# integration checkpoint\r\n")
    restarted = agent.AgentRuntime(config, log=lambda message: None)
    restarted.cycle(now=100)
    assert restarted.client_id == known_identity
    assert "strict.test" in hosts.read_text()
    assert state.exists()
    agent.clear_hosts(str(hosts))
    assert hosts.read_bytes() == b"# integration checkpoint\r\n"


def test_explicit_unassigned_policy_is_confirmed_after_release(tmp_path):
    with live_server() as (_, origin, client):
        hosts = tmp_path / "hosts"
        state = tmp_path / "state.json"
        client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["example.com"]}}).raise_for_status()
        runtime = agent.AgentRuntime(agent.AgentConfig(server=origin, devid="integration-pc", invitation="e2e-invitation", hosts_path=str(hosts), state_path=str(state), interval=1), log=lambda message: None)
        runtime.cycle(now=0)
        client.post("/api/v1/assignment_rules", json={"id": "release", "target_vdom": "Empty"}).raise_for_status()
        runtime.cycle(now=2)
        assert "example.com" not in hosts.read_text()
        detail = client.get("/api/v1/endpoints/detail", params={"devid": "integration-pc"}).json()
        assert detail["desired_profile"] is None
        assert detail["config_version"] == 0 and detail["applied_vdom"] == "Empty"
        assert detail["last_error"] == ""
