"""Tamper events on the server: device uploads, validation, retention and the panel event list."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.auth import AdminService
from app.events import BlockEvent, InMemoryEventStore, TamperEvent, current_hour
from app.service import EmsService

KINDS = ["dns_rule_restored", "wfp_restored", "browser_policy_restored", "hosts_restored", "service_config_restored",
         "watchdog_restored", "service_started_by_watchdog", "unexpected_exit"]


def stamp(when: datetime) -> str:
    return when.isoformat().replace("+00:00", "Z")


def setup(store, **options):
    admins = AdminService(secret="tamper-events-test-secret-0123456789")
    admins.add_admin("operator", "pw")
    client = TestClient(create_app(EmsService(require_invitation=False), admin_service=admins, event_store=store, **options))
    device = client.post("/fct/api/public/v1/register/", json={"devid": "RSM-SP-002"}).json()
    token = client.post("/api/v1/auth/login", json={"username": "operator", "password": "pw"}).json()["token"]
    return client, device, {"Authorization": f"Bearer {device['device_token']}"}, {"Authorization": f"Bearer {token}"}


def upload(client, device, auth, events, dropped=0):
    return client.post("/fct/api/public/v1/tamper/", headers=auth,
                       json={"client_id": device["client_id"], "events": events, "dropped": dropped})


def event(kind="dns_rule_restored", at=None, detail="NRPT rule routing DNS to the agent was recreated"):
    return {"at": stamp(at or datetime.now(UTC).replace(microsecond=0)), "kind": kind, "detail": detail}


def test_agents_report_known_tamper_kinds():
    store = InMemoryEventStore()
    client, device, auth, _ = setup(store)
    response = upload(client, device, auth, [event(kind) for kind in KINDS])
    assert response.status_code == 200 and response.json() == {"accepted": len(KINDS), "rejected": 0}
    stored = store.recent_tamper(20)
    assert {item.kind for item in stored} == set(KINDS)
    assert all(item.devid == "RSM-SP-002" for item in stored)
    assert upload(client, device, {}, [event()]).status_code == 401


def test_invalid_tamper_rows_are_skipped():
    store = InMemoryEventStore()
    client, device, auth, _ = setup(store)
    now = datetime.now(UTC).replace(microsecond=0)
    response = upload(client, device, auth, [
        event(),
        event(at=now + timedelta(hours=2)),
        event(at=now - timedelta(days=31)),
        {"at": "yesterday", "kind": "unexpected_exit", "detail": "x"},
    ])
    assert response.json() == {"accepted": 1, "rejected": 3}


@pytest.mark.parametrize("payload", [
    {"events": [event(kind="disabled_av")]},
    {"events": [event(detail="x" * 201)]},
    {"events": [event()] * 201},
    {"events": [{**event(), "user": "kenzo"}]},
    {"events": [], "dropped": -1},
])
def test_malformed_tamper_uploads_are_refused(payload):
    store = InMemoryEventStore()
    client, device, auth, _ = setup(store)
    response = client.post("/fct/api/public/v1/tamper/", headers=auth, json={"client_id": device["client_id"], **payload})
    assert response.status_code == 422
    assert store.recent_tamper(10) == []


def test_dropped_tamper_events_are_kept_as_a_row():
    store = InMemoryEventStore()
    client, device, auth, _ = setup(store)
    upload(client, device, auth, [], dropped=7)
    [row] = store.recent_tamper(10)
    assert (row.kind, row.detail) == ("dropped", "7 tamper events not recorded by the agent limit")


def test_old_tamper_events_are_purged_with_the_block_log():
    store = InMemoryEventStore()
    old = datetime.now(UTC) - timedelta(days=9)
    store.add_tamper([TamperEvent(devid="pc", at=old, kind="unexpected_exit", detail="x")])
    client, device, auth, _ = setup(store, event_retention_days=7)
    upload(client, device, auth, [event()])
    assert [item.kind for item in store.recent_tamper(10)] == ["dns_rule_restored"]


def test_the_panel_lists_tamper_and_block_events_newest_first():
    store = InMemoryEventStore()
    client, device, auth, admin = setup(store)
    now = datetime.now(UTC).replace(microsecond=0)
    store.add([BlockEvent(devid="RSM-SP-001", hour=current_hour() - timedelta(hours=1), domain="tiktok.com",
                          reason="rule", category="", count=3)])
    upload(client, device, auth, [event(at=now)])
    rows = client.get("/api/v1/events?limit=10", headers=admin).json()
    assert [(row["kind"], row["devid"]) for row in rows] == [("tamper", "RSM-SP-002"), ("web_block", "RSM-SP-001")]
    tamper = rows[0]
    assert tamper["detail"] == "NRPT rule routing DNS to the agent was recreated"
    assert tamper["reason"] == "dns_rule_restored"
    assert datetime.fromisoformat(tamper["at"]) == now
    assert len(client.get("/api/v1/events?limit=1", headers=admin).json()) == 1


def test_postgres_store_keeps_tamper_events():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    from app.events import PostgresEventStore

    store = PostgresEventStore(dsn)
    store.init_schema()
    with store._conn.cursor() as cur:
        cur.execute("TRUNCATE tamper_events")
    now = datetime.now(UTC).replace(microsecond=0)
    store.add_tamper([TamperEvent(devid="pc", at=now, kind="unexpected_exit", detail="x"),
                      TamperEvent(devid="pc", at=now - timedelta(days=40), kind="wfp_restored", detail="y")])
    assert [item.kind for item in store.recent_tamper(10)] == ["unexpected_exit", "wfp_restored"]
    assert store.purge_tamper(now - timedelta(days=30)) == 1
    store.close()
