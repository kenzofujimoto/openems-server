"""Authenticated inventory snapshots and actual application/device control events."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import RegisterRequest
from app.service import EmsService


@pytest.fixture
def harness():
    service = EmsService(valid_invitations={"inventory-test", "other-test"})
    endpoint = service.register(RegisterRequest(devid="pc", invitation="inventory-test"))
    other = service.register(RegisterRequest(devid="other", invitation="other-test"))
    admin = AdminService()
    admin.add_admin("operator", "test-password")
    audit = InMemoryAuditLog()
    client = TestClient(create_app(service, admin_service=admin, audit_log=audit))
    management = {"Authorization": "Bearer " + admin.issue_token("operator", "admin")}
    device = {"Authorization": "Bearer " + endpoint.device_token}
    return service, client, endpoint, other, management, device, audit


def snapshot(client_id):
    now = datetime.now(UTC).isoformat()
    return {"client_id": client_id, "collected_at": now, "applications": [
        {"name": "Example", "path": r"C:\Apps\one.exe", "sha256": "ab" * 32,
         "publisher": "Publisher", "version": "1.0", "running": True},
    ], "usb_devices": [
        {"instance_id": r"USBSTOR\DISK\serial", "vid": "0781", "pid": "abcd", "manufacturer": "Example",
         "product": "USB disk", "serial": "serial", "class": "storage", "drive_letters": ["E:"],
         "present": True, "first_seen": now, "last_seen": now},
    ]}


def test_device_inventory_is_scoped_to_authenticated_identity_and_audited_on_read(harness):
    _, client, endpoint, other, management, device, audit = harness
    path = "/fct/api/public/v1/inventory/"
    assert client.post(path, json=snapshot(endpoint.client_id)).status_code == 401
    assert client.post(path, json=snapshot(other.client_id), headers=device).status_code == 401
    assert client.post(path, json=snapshot(endpoint.client_id), headers=device).status_code == 200
    result = client.get("/api/v1/endpoints/inventory", params={"devid": "pc"}, headers=management)
    assert result.status_code == 200
    assert result.json()["applications"][0]["sha256"] == "ab" * 32
    assert result.json()["usb_devices"][0]["instance_id"] == r"USBSTOR\DISK\serial"
    assert result.json()["devid"] == "pc"
    assert "client_id" not in result.json()
    assert any(entry.action == "inventory.read" for entry in audit.list())
    assert client.get("/api/v1/endpoints/inventory", params={"devid": "other"}, headers=management).json()["applications"] == []


def test_inventory_replacement_rejects_old_or_naive_snapshots_and_bounds_fields(harness):
    _, client, endpoint, _, management, device, _ = harness
    payload = snapshot(endpoint.client_id)
    path = "/fct/api/public/v1/inventory/"
    assert client.post(path, json=payload, headers=device).status_code == 200
    stale = {**payload, "collected_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(), "applications": []}
    assert client.post(path, json=stale, headers=device).status_code == 409
    naive = {**payload, "collected_at": "2026-10-25T12:00:00"}
    assert client.post(path, json=naive, headers=device).status_code == 422
    invalid = {**payload, "applications": [{**payload["applications"][0], "path": "x" * 4097}]}
    assert client.post(path, json=invalid, headers=device).status_code == 422
    assert len(client.get("/api/v1/endpoints/inventory", params={"devid": "pc"}, headers=management).json()["applications"]) == 1


def test_control_events_reach_feed_and_real_dashboard_totals(harness):
    _, client, endpoint, _, management, device, _ = harness
    now = datetime.now(UTC).isoformat()
    rows = [{"at": now, "kind": kind, "target": target, "rule_id": "policy-rule"} for kind, target in (
        ("usb_block", "USB disk"), ("app_block", "one.exe"), ("app_network_block", "two.exe"),
    )]
    response = client.post("/fct/api/public/v1/control_events/", json={"client_id": endpoint.client_id, "events": rows}, headers=device)
    assert response.status_code == 200 and response.json()["accepted"] == 3
    feed = client.get("/api/v1/events", headers=management).json()
    assert {event["kind"] for event in feed} == {"usb_block", "app_block", "app_network_block"}
    assert all(event["devid"] == "pc" for event in feed)
    totals = client.get("/api/v1/stats/overview", headers=management).json()["blocks_by_day"][-1]
    assert totals["apps"] == 2 and totals["usb"] == 1


def test_control_events_deduplicate_retries_and_expire_old_data_on_read(harness):
    _, client, endpoint, _, management, device, _ = harness
    now = datetime.now(UTC).isoformat()
    row = {"at": now, "kind": "usb_read_only", "target": "USB disk", "rule_id": "read-only"}
    payload = {"client_id": endpoint.client_id, "events": [row]}
    for _ in range(2):
        assert client.post("/fct/api/public/v1/control_events/", json=payload, headers=device).status_code == 200
    assert len(client.get("/api/v1/events", headers=management).json()) == 1
    old = {**row, "at": (datetime.now(UTC) - timedelta(days=40)).isoformat()}
    reply = client.post("/fct/api/public/v1/control_events/", json={**payload, "events": [old]}, headers=device).json()
    assert reply == {"accepted": 0, "rejected": 1}


def test_control_events_require_a_rule_identity_including_batch_setup(harness):
    _, client, endpoint, _, management, device, _ = harness
    row = {"at": datetime.now(UTC).isoformat(), "kind": "app_control_applied", "target": "execution policy"}
    url = "/fct/api/public/v1/control_events/"
    payload = {"client_id": endpoint.client_id, "events": [row]}
    assert client.post(url, json=payload, headers=device).status_code == 422
    assert client.post(url, json={**payload, "events": [{**row, "rule_id": ""}]}, headers=device).status_code == 422
    assert client.post(url, json={**payload, "events": [{**row, "rule_id": "execution-policy"}]}, headers=device).status_code == 200
    overview = client.get("/api/v1/stats/overview", headers=management).json()
    assert sum(day["apps"] for day in overview["blocks_by_day"]) == 0


def test_postgres_inventory_serializes_concurrent_purges(monkeypatch):
    # 2026-10-27 panel review: overview and events load in parallel, both purge, and two
    # transactions on the one shared connection nested (psycopg OutOfOrderTransactionNesting).
    import contextlib
    import threading
    import time

    import psycopg

    from app.inventory import PostgresInventoryStore

    class SharedConnection:
        def __init__(self):
            self.active = 0
            self.overlaps = 0

        @contextlib.contextmanager
        def transaction(self):
            self.active += 1
            if self.active > 1:
                self.overlaps += 1
            try:
                time.sleep(0.05)
                yield
            finally:
                self.active -= 1

        def execute(self, *args):
            time.sleep(0.01)

    connection = SharedConnection()
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connection)
    store = PostgresInventoryStore("postgresql://fake")
    workers = [threading.Thread(target=store.purge, args=(datetime.now(UTC),)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert connection.overlaps == 0


def test_events_can_be_read_for_one_machine_and_each_read_is_audited(harness):
    _, client, endpoint, other, management, device, audit = harness
    now = datetime.now(UTC).isoformat()
    other_device = {"Authorization": "Bearer " + other.device_token}
    mine = {"client_id": endpoint.client_id, "events": [{"at": now, "kind": "app_block", "target": "game.exe", "rule_id": "catalog-1"}]}
    theirs = {"client_id": other.client_id, "events": [{"at": now, "kind": "usb_block", "target": "USB disk", "rule_id": "default"}]}
    assert client.post("/fct/api/public/v1/control_events/", json=mine, headers=device).status_code == 200
    assert client.post("/fct/api/public/v1/control_events/", json=theirs, headers=other_device).status_code == 200
    feed = client.get("/api/v1/events", params={"devid": "pc"}, headers=management).json()
    assert [(event["devid"], event["kind"]) for event in feed] == [("pc", "app_block")]
    assert any(entry.action == "events.read" and entry.target == "pc" for entry in audit.list())
    assert client.get("/api/v1/events", params={"devid": "missing"}, headers=management).status_code == 404
