"""Tests for the admin audit log."""

from __future__ import annotations

import pytest

from app.audit import AuditEntry, InMemoryAuditLog

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from app.api import create_app
from app.auth import AdminService
from app.service import EmsService


def test_inmemory_audit_newest_first_and_limit() -> None:
    log = InMemoryAuditLog()
    for i in range(5):
        log.record(AuditEntry(actor="a", action=f"act{i}"))
    assert [e.action for e in log.list(limit=3)] == ["act4", "act3", "act2"]


def test_postgres_audit_roundtrip() -> None:
    import os

    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    from app.audit import PostgresAuditLog

    log = PostgresAuditLog(dsn)
    log.init_schema()
    with log._conn.cursor() as cur:
        cur.execute("TRUNCATE audit_log")
    log.record(AuditEntry(actor="kenzo", action="rule.add", target="r1",
                          metadata={"priority": 10}))
    log.record(AuditEntry(actor="kenzo", action="profile.publish", target="Default"))
    entries = log.list(limit=10)
    assert entries[0].action == "profile.publish"  # newest first
    assert entries[1].metadata == {"priority": 10}


def test_actions_recorded_in_setup_mode() -> None:
    client = TestClient(create_app(EmsService(require_invitation=False), lab_mode=True))  # no admin -> setup mode
    client.post("/api/v1/profiles/Default", json={"x": 1})
    client.post("/api/v1/assignment_rules", json={"id": "r1", "target_vdom": "A"})
    client.delete("/api/v1/assignment_rules/r1")

    entries = client.get("/api/v1/audit").json()
    triples = {(e["action"], e["target"], e["actor"]) for e in entries}
    assert ("profile.publish", "Default", "setup") in triples
    assert ("rule.add", "r1", "setup") in triples
    assert ("rule.remove", "r1", "setup") in triples


def test_actor_is_admin_when_authenticated() -> None:
    admins = AdminService(secret="t")
    admins.add_admin("kenzo", "pw")
    client = TestClient(create_app(EmsService(require_invitation=False), admin_service=admins))
    token = client.post(
        "/api/v1/auth/login", json={"username": "kenzo", "password": "pw"}
    ).json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    client.post("/api/v1/profiles/Default", json={"x": 1}, headers=h)
    entries = client.get("/api/v1/audit", headers=h).json()
    assert entries[0]["actor"] == "kenzo"
    assert entries[0]["action"] == "profile.publish"
    assert entries[0]["target"] == "Default"
