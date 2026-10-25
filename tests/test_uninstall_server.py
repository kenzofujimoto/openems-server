"""Uninstall codes on the server (tamper-protection.md, part 5b): secret delivery, codes, release."""

from __future__ import annotations

import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.uninstall import (
    code,
    delivery_proof,
    derive_secret,
    master_key_from_text,
    release_token,
)
from app.api import build, create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import AssignmentRule, Condition
from app.service import EmsService
from app.uninstall_codes import InMemoryUninstallStore

MASTER = b"test-only-master-key-0123456789abcdef"
SECRET_ROUTE = "/fct/api/public/v1/uninstall_secret/"
ACK_ROUTE = "/fct/api/public/v1/uninstall_secret/ack/"
_ENVIRONMENT = ("OPENEMS_ADMIN", "OPENEMS_RECORD", "OPENEMS_LAB_MODE", "OPENEMS_DATABASE_URL",
                "OPENEMS_SESSION_SECRET", "OPENEMS_BASE_URL", "OPENEMS_REDIS_URL", "OPENEMS_ENROLLMENT_TOKEN",
                "OPENEMS_UNINSTALL_MASTER_KEY")


class Server:
    def __init__(self, master_key: bytes | None = MASTER, store=None) -> None:
        self.service = EmsService(require_invitation=False)
        self.audit = InMemoryAuditLog()
        admins = AdminService(secret="uninstall-server-test-secret-0123456789")
        admins.add_admin("operator", "pw")
        admins.add_admin("auditor", "pw", role="viewer")
        self.client = TestClient(create_app(self.service, admin_service=admins, audit_log=self.audit,
                                            uninstall_master_key=master_key, uninstall_store=store))
        self.admin = self._login("operator")
        self.viewer = self._login("auditor")

    def _login(self, username: str) -> dict[str, str]:
        token = self.client.post("/api/v1/auth/login", json={"username": username, "password": "pw"}).json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def register(self, devid: str, vdom: str = "Default") -> dict:
        device = self.client.post("/fct/api/public/v1/register/", json={"devid": devid, "vdom": vdom}).json()
        device["auth"] = {"Authorization": f"Bearer {device['device_token']}"}
        device["devid"] = devid
        return device

    def fetch_secret(self, device: dict):
        return self.client.post(SECRET_ROUTE, headers=device["auth"], json={"client_id": device["client_id"]})

    def ack(self, device: dict, proof: str):
        return self.client.post(ACK_ROUTE, headers=device["auth"], json={"client_id": device["client_id"], "proof": proof})

    def new_code(self, devid: str, headers: dict | None = None):
        return self.client.post("/api/v1/endpoints/uninstall_code", headers=headers or self.admin, json={"devid": devid})

    def release(self, scope: str, released: bool = True, headers: dict | None = None):
        return self.client.post("/api/v1/uninstall_release", headers=headers or self.admin,
                                json={"scope": scope, "released": released})

    def assigned(self, device: dict) -> dict:
        response = self.client.get("/fct/api/public/v1/config/assigned/", headers=device["auth"],
                                   params={"client_id": device["client_id"]})
        assert response.status_code == 200, response.text
        return response.json()


def secret_of(device: dict) -> bytes:
    return derive_secret(MASTER, device["client_id"])


# --- secret delivery -----------------------------------------------------------------------------------------------


def test_the_agent_receives_its_own_secret_until_it_confirms_delivery():
    server = Server()
    device = server.register("RSM-SP-010")
    first = server.fetch_secret(device)
    assert first.status_code == 200 and first.json() == {"secret": secret_of(device).hex()}
    assert server.fetch_secret(device).json() == first.json(), "a lost answer can be fetched again"
    assert server.ack(device, delivery_proof(secret_of(device))).status_code == 200
    again = server.fetch_secret(device)
    assert again.status_code == 409 and "secret" not in again.json()
    assert server.ack(device, delivery_proof(secret_of(device))).status_code == 200, "repeated ack is harmless"


def test_secret_routes_require_the_device_credential():
    server = Server()
    device = server.register("RSM-SP-011")
    other = server.register("RSM-SP-012")
    assert server.client.post(SECRET_ROUTE, json={"client_id": device["client_id"]}).status_code == 401
    stolen = server.client.post(SECRET_ROUTE, headers=other["auth"], json={"client_id": device["client_id"]})
    assert stolen.status_code == 401
    assert server.client.post(ACK_ROUTE, json={"client_id": device["client_id"], "proof": "0" * 64}).status_code == 401


@pytest.mark.parametrize("proof", ["0" * 64, release_token(derive_secret(MASTER, "x")), "not-hex", ""])
def test_a_wrong_delivery_proof_does_not_close_delivery(proof):
    server = Server()
    device = server.register("RSM-SP-013")
    server.fetch_secret(device)
    assert server.ack(device, proof).status_code in (403, 422)
    assert server.fetch_secret(device).status_code == 200


def test_an_admin_can_reopen_delivery_for_an_agent_that_lost_its_secret():
    server = Server()
    device = server.register("RSM-SP-014")
    server.fetch_secret(device)
    server.ack(device, delivery_proof(secret_of(device)))
    route = "/api/v1/endpoints/uninstall_secret/reset"
    assert server.client.post(route, headers=server.viewer, json={"devid": "RSM-SP-014"}).status_code == 403
    assert server.client.post(route, headers=server.admin, json={"devid": "missing"}).status_code == 404
    assert server.client.post(route, headers=server.admin, json={"devid": "RSM-SP-014"}).status_code == 200
    assert server.fetch_secret(device).json() == {"secret": secret_of(device).hex()}
    [entry] = [item for item in server.audit.list() if item.action == "endpoint.uninstall_secret.reset"]
    assert (entry.actor, entry.target) == ("operator", "RSM-SP-014")


def test_a_new_client_id_gets_a_new_secret_delivery_and_fresh_counter():
    server = Server()
    device = server.register("RSM-SP-015")
    server.fetch_secret(device)
    server.ack(device, delivery_proof(secret_of(device)))
    server.new_code("RSM-SP-015")
    renamed = server.client.post("/fct/api/public/v1/update_client_id/", headers=device["auth"],
                                 json={"client_id": device["client_id"]}).json()["client_id"]
    device = {**device, "client_id": renamed}
    assert server.fetch_secret(device).json() == {"secret": secret_of(device).hex()}
    assert server.new_code("RSM-SP-015").json()["code"] == code(secret_of(device), 1)


# --- codes ---------------------------------------------------------------------------------------------------------


def test_admins_get_consecutive_codes_and_the_audit_never_holds_them():
    server = Server()
    device = server.register("RSM-SP-020")
    issued = [server.new_code("RSM-SP-020").json() for _ in range(3)]
    assert [item["counter"] for item in issued] == [1, 2, 3]
    assert [item["code"] for item in issued] == [code(secret_of(device), counter) for counter in (1, 2, 3)]
    assert all(item["devid"] == "RSM-SP-020" for item in issued)
    entries = [item for item in server.audit.list() if item.action == "endpoint.uninstall_code"]
    assert [entry.metadata for entry in reversed(entries)] == [{"counter": 1}, {"counter": 2}, {"counter": 3}]
    assert all(entry.target == "RSM-SP-020" and entry.actor == "operator" for entry in entries)
    recorded = repr(server.audit.list()) + server.client.get("/api/v1/audit", headers=server.admin).text
    assert not any(item["code"] in recorded for item in issued)


def test_codes_are_admin_only_and_need_a_known_machine():
    server = Server()
    server.register("RSM-SP-021")
    assert server.new_code("RSM-SP-021", headers=server.viewer).status_code == 403
    assert server.client.post("/api/v1/endpoints/uninstall_code", json={"devid": "RSM-SP-021"}).status_code == 401
    assert server.new_code("missing").status_code == 404
    assert server.client.post("/api/v1/endpoints/uninstall_code", headers=server.admin, json={}).status_code == 422


def test_a_revoked_machine_still_gets_codes_because_its_agent_may_remain_installed():
    server = Server()
    device = server.register("RSM-SP-022")
    server.client.post("/api/v1/endpoints/revoke", headers=server.admin, json={"devid": "RSM-SP-022"})
    assert server.new_code("RSM-SP-022").json()["code"] == code(secret_of(device), 1)


def test_concurrent_code_requests_never_reuse_a_counter():
    store = InMemoryUninstallStore()
    with ThreadPoolExecutor(max_workers=8) as pool:
        counters = list(pool.map(lambda _: store.next_counter("client-1"), range(200)))
    assert sorted(counters) == list(range(1, 201))
    assert store.next_counter("client-2") == 1


# --- release -------------------------------------------------------------------------------------------------------


def test_a_group_release_reaches_only_machines_in_that_group():
    server = Server()
    inside = server.register("RSM-SP-030", vdom="Lab")
    outside = server.register("RSM-SP-031")
    assert "uninstall_release" not in server.assigned(inside)
    assert server.release("Lab", headers=server.viewer).status_code == 403
    assert server.release("Lab").json() == {"scope": "Lab", "released": True}
    assert server.assigned(inside)["uninstall_release"] == release_token(secret_of(inside))
    assert server.assigned(inside).get("unassigned") is True, "also sent with no policy published"
    assert "uninstall_release" not in server.assigned(outside)
    [entry] = [item for item in server.audit.list() if item.action == "uninstall.release"]
    assert (entry.actor, entry.target) == ("operator", "Lab")


def test_a_release_follows_the_effective_group_and_the_fleet_scope():
    server = Server()
    moved = server.register("RSM-SP-032")
    other = server.register("RSM-SP-033", vdom="Office")
    server.service.add_rule(AssignmentRule(id="lab", target_vdom="Lab",
                                           conditions=[Condition(field="vdom", op="equals", value="Default")]))
    server.release("Lab")
    assert server.assigned(moved)["uninstall_release"] == release_token(secret_of(moved))
    server.service.remove_rule("lab")
    server.release("Lab", released=False)
    assert "uninstall_release" not in server.assigned(moved)
    server.release("*")
    assert server.assigned(other)["uninstall_release"] == release_token(secret_of(other))
    listed = server.client.get("/api/v1/uninstall_release", headers=server.viewer).json()
    assert [(row["scope"], row["released_by"]) for row in listed] == [("*", "operator")]
    assert {item.action for item in server.audit.list()} >= {"uninstall.release", "uninstall.release.revoke"}


@pytest.mark.parametrize("payload", [{"scope": "", "released": True}, {"scope": "x" * 129, "released": True},
                                     {"scope": "Lab"}, {"scope": "Lab", "released": "yes"}])
def test_malformed_release_requests_are_refused(payload):
    server = Server()
    assert server.client.post("/api/v1/uninstall_release", headers=server.admin, json=payload).status_code == 422


# --- configuration -------------------------------------------------------------------------------------------------


def test_without_a_master_key_the_feature_is_off_and_agents_see_nothing_new():
    server = Server(master_key=None)
    device = server.register("RSM-SP-040")
    assert server.fetch_secret(device).status_code == 503
    assert server.ack(device, "0" * 64).status_code == 503
    assert server.new_code("RSM-SP-040").status_code == 503
    assert server.release("*").status_code == 503
    assert "uninstall_release" not in server.assigned(device)


def test_short_master_keys_are_refused():
    with pytest.raises(ValueError):
        Server(master_key=b"too-short")


@pytest.fixture()
def clean_environment(monkeypatch):
    for key in _ENVIRONMENT:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_build_reads_the_master_key_from_the_environment(clean_environment):
    clean_environment.setenv("OPENEMS_LAB_MODE", "1")
    clean_environment.setenv("OPENEMS_UNINSTALL_MASTER_KEY", f"  {MASTER.decode()}\n")
    client = TestClient(build())
    device = client.post("/fct/api/public/v1/register/", json={"devid": "RSM-SP-041"}).json()
    response = client.post(SECRET_ROUTE, json={"client_id": device["client_id"]})
    assert response.json() == {"secret": derive_secret(MASTER, device["client_id"]).hex()}


def test_an_empty_master_key_variable_leaves_the_feature_off(clean_environment):
    # docker-compose passes ${OPENEMS_UNINSTALL_MASTER_KEY:-} as an empty string when .env has no key.
    clean_environment.setenv("OPENEMS_LAB_MODE", "1")
    clean_environment.setenv("OPENEMS_UNINSTALL_MASTER_KEY", "")
    client = TestClient(build())
    device = client.post("/fct/api/public/v1/register/", json={"devid": "RSM-SP-042"}).json()
    assert client.post(SECRET_ROUTE, json={"client_id": device["client_id"]}).status_code == 503


def test_compose_passes_the_master_key_without_requiring_it():
    compose = (Path(__file__).resolve().parent.parent / "docker-compose.yml").read_text(encoding="utf-8")
    assert "OPENEMS_UNINSTALL_MASTER_KEY: ${OPENEMS_UNINSTALL_MASTER_KEY:-}" in compose


def _new_env(path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is not available")
    script = Path(__file__).resolve().parent.parent / "deploy" / "new-env.ps1"
    return subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Path", str(path),
                           *extra], capture_output=True, text=True, timeout=120, check=False)


def _env_values(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line)


def test_new_env_generates_a_master_key_and_keeps_it_on_force(tmp_path: Path):
    path = tmp_path / ".env"
    first = _new_env(path)
    assert first.returncode == 0, first.stderr
    key = _env_values(path)["OPENEMS_UNINSTALL_MASTER_KEY"]
    assert len(master_key_from_text(key)) >= 48
    assert "cofre" in first.stdout or "vault" in first.stdout.lower(), "tells the operator to store the key"
    replaced = _new_env(path, "-Force")
    assert replaced.returncode == 0, replaced.stderr
    values = _env_values(path)
    assert values["OPENEMS_UNINSTALL_MASTER_KEY"] == key, "a new key would orphan every installed agent's secret"
    assert key not in replaced.stdout, "an existing key is not shown again"


def test_build_rejects_a_short_master_key_without_exposing_it(clean_environment):
    clean_environment.setenv("OPENEMS_UNINSTALL_MASTER_KEY", "short-sensitive-key")
    with pytest.raises(ValueError, match="OPENEMS_UNINSTALL_MASTER_KEY") as error:
        build()
    assert "short-sensitive-key" not in str(error.value)


def test_postgres_uninstall_store_counts_atomically_and_keeps_releases():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    from app.uninstall_codes import PostgresUninstallStore

    def count_once(_: int) -> int:
        worker = PostgresUninstallStore(dsn)
        try:
            return worker.next_counter("client-1")
        finally:
            worker.close()

    store = PostgresUninstallStore(dsn)
    store.init_schema()
    try:
        with store._conn.cursor() as cur:
            cur.execute("DELETE FROM uninstall_state; DELETE FROM uninstall_releases")
        with ThreadPoolExecutor(max_workers=8) as pool:
            counters = list(pool.map(count_once, range(40)))
        assert sorted(counters) == list(range(1, 41))
        assert not store.secret_acked("client-1")
        store.set_secret_acked("client-1", True)
        assert store.secret_acked("client-1") and not store.secret_acked("client-2")
        store.set_release("Lab", True, "operator")
        store.set_release("Lab", True, "other")
        assert [(row.scope, row.released_by) for row in store.releases()] == [("Lab", "operator")]
        store.set_release("Lab", False, "operator")
        assert store.releases() == []
    finally:
        store.close()
