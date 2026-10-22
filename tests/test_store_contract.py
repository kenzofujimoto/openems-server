"""Contract tests that every Store implementation must satisfy.

InMemoryStore runs always. PostgresStore runs only when OPENEMS_TEST_DSN points
at a reachable database, e.g.:

    docker run --rm -e POSTGRES_PASSWORD=pw -p 5432:5432 postgres:16
    OPENEMS_TEST_DSN=postgresql://postgres:pw@localhost:5432/postgres pytest
"""

from __future__ import annotations

import os

import pytest

from app.models import Endpoint, EndpointStatus
from app.stores import InMemoryStore, PostgresStore


def _make_inmemory():
    return InMemoryStore()


def _make_postgres():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set; skipping PostgresStore contract test")
    store = PostgresStore(dsn)
    store.init_schema()
    # clean slate for the test run
    with store._conn.cursor() as cur:  # noqa: SLF001 - test-only reset
        cur.execute("TRUNCATE endpoints")
    return store


@pytest.fixture(params=[_make_inmemory, _make_postgres], ids=["inmemory", "postgres"])
def store(request):
    return request.param()


def _ep(devid: str, client_id: str, tags: list[str] | None = None) -> Endpoint:
    return Endpoint(
        devid=devid,
        client_id=client_id,
        hostname="pc",
        os="Windows",
        status=EndpointStatus.REGISTERED,
        host_tags=tags or [],
    )


def test_upsert_then_get_by_client_id(store) -> None:
    store.upsert(_ep("DEV-1", "cid-1"))
    got = store.get_by_client_id("cid-1")
    assert got is not None and got.devid == "DEV-1"


def test_get_by_devid(store) -> None:
    store.upsert(_ep("DEV-1", "cid-1"))
    got = store.get_by_devid("DEV-1")
    assert got is not None and got.client_id == "cid-1"


def test_missing_returns_none(store) -> None:
    assert store.get_by_client_id("nope") is None
    assert store.get_by_devid("nope") is None


def test_upsert_replaces_same_devid(store) -> None:
    store.upsert(_ep("DEV-1", "cid-1"))
    store.upsert(_ep("DEV-1", "cid-2", tags=["compliant"]))
    assert store.get_by_client_id("cid-2").host_tags == ["compliant"]
    assert len(store.all()) == 1


def test_all_lists_every_endpoint(store) -> None:
    store.upsert(_ep("DEV-1", "cid-1"))
    store.upsert(_ep("DEV-2", "cid-2"))
    assert {e.devid for e in store.all()} == {"DEV-1", "DEV-2"}


def test_rotated_identifier_stops_resolving(store) -> None:
    store.upsert(_ep("DEV-1", "old"))
    endpoint = store.get_by_devid("DEV-1")
    endpoint.client_id = "new"
    store.upsert(endpoint)
    assert store.get_by_client_id("old") is None
    assert store.get_by_client_id("new").devid == "DEV-1"


def test_credentials_and_full_policy_status_roundtrip(store) -> None:
    from datetime import datetime, timezone
    endpoint = _ep("DEV-1", "client")
    endpoint.credential_hash = "hashed-token"
    endpoint.device_token = "never-persist-plaintext"
    endpoint.config_version = 4
    endpoint.applied_vdom = "Strict"
    endpoint.applied_digest = "a" * 64
    endpoint.last_error = "pending retry"
    endpoint.last_applied = datetime.now(timezone.utc)
    store.upsert(endpoint)
    restored = store.get_by_devid("DEV-1")
    assert restored.credential_hash == "hashed-token"
    assert restored.device_token == ""
    assert restored.config_version == 4
    assert restored.applied_vdom == "Strict"
    assert restored.applied_digest == "a" * 64
    assert restored.last_error == "pending retry"
    assert restored.last_applied == endpoint.last_applied


def test_create_cannot_overwrite_existing_identity(store) -> None:
    first = _ep("DEV-1", "first")
    assert store.create(first)
    assert not store.create(_ep("DEV-1", "attacker"))
    assert store.get_by_devid("DEV-1").client_id == "first"
