"""Storage contracts run identically in memory and a disposable PostgreSQL schema."""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.enrollment import InMemoryEnrollmentStore, PostgresEnrollmentStore
from app.inventory import InMemoryInventoryStore, PostgresInventoryStore
from app.stores import (
    InMemoryAdminStore,
    InMemoryProfileStore,
    PostgresAdminStore,
    PostgresProfileStore,
    ProfilePreconditionError,
)


@pytest.fixture(params=["memory", "postgres"])
def storage(request):
    if request.param == "memory":
        yield {"inventory": InMemoryInventoryStore(), "admins": InMemoryAdminStore(),
               "profiles": InMemoryProfileStore(), "invitations": InMemoryEnrollmentStore()}
        return
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("disposable OPENEMS_TEST_DSN is not configured")
    import psycopg
    from psycopg.conninfo import make_conninfo

    schema = "controls_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(psycopg.sql.SQL("CREATE SCHEMA {}").format(psycopg.sql.Identifier(schema)))
    isolated = make_conninfo(dsn, options=f"-c search_path={schema}")
    stores = {"inventory": PostgresInventoryStore(isolated), "admins": PostgresAdminStore(isolated),
              "profiles": PostgresProfileStore(isolated), "invitations": PostgresEnrollmentStore(isolated)}
    try:
        for store in stores.values():
            store.init_schema()
        yield stores
    finally:
        for store in stores.values():
            store.close()
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(psycopg.sql.Identifier(schema)))


def test_inventory_snapshots_are_monotonic_and_expire(storage):
    store = storage["inventory"]
    now = datetime.now(UTC)
    snapshot = {"devid": "pc", "collected_at": now.isoformat(), "applications": [], "usb_devices": []}
    assert store.snapshot("pc") is None
    assert store.replace(snapshot)
    assert not store.replace({**snapshot, "collected_at": (now - timedelta(seconds=1)).isoformat()})
    assert store.snapshot("pc") == snapshot
    store.purge(now + timedelta(seconds=1))
    assert store.snapshot("pc") is None


def test_event_retries_are_idempotent_and_totals_are_real(storage):
    store = storage["inventory"]
    now = datetime.now(UTC)
    events = [{"devid": "pc", "at": now.isoformat(), "kind": kind, "target": "device or app", "rule_id": "rule"}
              for kind in ("usb_block", "app_block", "app_network_block")]
    store.add_events(events)
    store.add_events(events)
    assert len(store.recent_events(50)) == 3
    assert len(store.recent_events(1)) == 1
    assert store.daily_totals(now - timedelta(seconds=1)) == {now.date().isoformat(): {"apps": 2, "usb": 1}}
    assert store.daily_totals(now + timedelta(seconds=1)) == {}
    store.purge(now + timedelta(seconds=1))
    assert store.recent_events(50) == []


def test_app_policy_setup_events_do_not_inflate_actual_block_totals(storage):
    store = storage["inventory"]
    now = datetime.now(UTC)
    store.add_events([{"devid": "pc", "at": now.isoformat(), "kind": kind, "target": "one.exe", "rule_id": "rule"}
                      for kind in ("app_control_applied", "app_network_policy")])
    assert len(store.recent_events(10)) == 2
    assert store.daily_totals(now - timedelta(seconds=1)) == {}


def test_administrator_mutations_protect_last_writer_and_existing_credentials(storage):
    store = storage["admins"]
    assert store.manage("admin", "hash", "admin", create=True)
    assert not store.manage("admin", "replace", "viewer", create=True)
    with pytest.raises(ValueError, match="last administrator"):
        store.manage("admin", None, "viewer")
    assert not store.manage("unknown", None, None, delete=True)
    assert store.manage("viewer", "viewer-hash", "viewer", create=True)
    assert store.all() == [{"username": "admin", "role": "admin"}, {"username": "viewer", "role": "viewer"}]
    assert store.manage("viewer", "new-hash", None)
    assert store.get("viewer") == ("new-hash", "viewer")
    assert store.manage("viewer", None, None, delete=True)
    store.put("root", "root-hash", "superadmin")
    with pytest.raises(PermissionError):
        store.manage("root", None, None, delete=True)
    assert store.manage("root", None, None, delete=True, allow_superadmin=True)


def test_invitation_management_never_recovers_a_token(storage):
    store = storage["invitations"]
    expires = datetime.now(UTC) + timedelta(hours=1)
    store.add("test-only-token", "Default", 2, expires)
    assert store.consume("test-only-token", "Default")
    [item] = store.list()
    assert item["remaining"] == 1 and item["vdom"] == "Default"
    assert "test-only-token" not in str(item)
    assert store.revoke(item["id"])
    assert not store.revoke(item["id"])
    assert not store.consume("test-only-token", "Default")


def test_revoked_bootstrap_invitation_cannot_be_reopened_by_server_restart(storage):
    store = storage["invitations"]
    expires = datetime.now(UTC) + timedelta(hours=1)
    store.add("bootstrap-token", "Default", 2, expires)
    [item] = store.list()
    assert store.revoke(item["id"])
    store.add("bootstrap-token", "Default", 2, expires)
    assert not store.consume("bootstrap-token", "Default")
    assert store.list() == []


def test_profile_compare_and_swap_never_overwrites_a_newer_editor(storage):
    store = storage["profiles"]
    with pytest.raises(ProfilePreconditionError):
        store.publish("Default", {}, "ab" * 32)
    first = store.publish("Default", {"a": 1})
    second = store.publish("Default", {"b": 2}, first.digest)
    assert second.version == 2
    with pytest.raises(ProfilePreconditionError):
        store.publish("Default", {"lost": True}, first.digest)
    assert store.get("Default").body == {"b": 2}
