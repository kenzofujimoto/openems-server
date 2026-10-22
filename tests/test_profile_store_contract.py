"""Contract tests every ProfileStore implementation must satisfy.

InMemoryProfileStore runs always; PostgresProfileStore runs when OPENEMS_TEST_DSN
points at a reachable database (see test_store_contract.py for how to spin one up).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from app.models import Profile
from app.stores import InMemoryProfileStore, PostgresProfileStore


def _make_inmemory():
    return InMemoryProfileStore()


def _make_postgres():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set; skipping PostgresProfileStore test")
    import psycopg
    from psycopg.conninfo import make_conninfo
    schema = "test_profiles_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(psycopg.sql.SQL("CREATE SCHEMA {}").format(psycopg.sql.Identifier(schema)))
    store = PostgresProfileStore(make_conninfo(dsn, options=f"-c search_path={schema}"))
    store.init_schema()
    store._test_schema = schema
    return store


@pytest.fixture(params=[_make_inmemory, _make_postgres], ids=["inmemory", "postgres"])
def store(request):
    instance = request.param()
    yield instance
    if isinstance(instance, PostgresProfileStore):
        import psycopg
        instance._conn.execute(psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(
            psycopg.sql.Identifier(instance._test_schema)))
        instance.close()


def test_missing_returns_none(store) -> None:
    assert store.get("Default") is None


def test_put_then_get(store) -> None:
    store.put(Profile(vdom="Default", version=1, body={"av": "on"}))
    got = store.get("Default")
    assert got is not None
    assert got.version == 1 and got.body == {"av": "on"}


def test_put_overwrites_same_vdom(store) -> None:
    store.put(Profile(vdom="Default", version=1, body={"av": "on"}))
    store.put(Profile(vdom="Default", version=2, body={"av": "off"}))
    got = store.get("Default")
    assert got.version == 2 and got.body == {"av": "off"}


def test_all_lists_profiles(store) -> None:
    store.put(Profile(vdom="Default", version=1))
    store.put(Profile(vdom="Branch", version=1))
    assert {p.vdom for p in store.all()} == {"Default", "Branch"}


def test_publish_increments_versions_atomically_under_concurrency(store) -> None:
    with ThreadPoolExecutor(max_workers=8) as executor:
        profiles = list(executor.map(lambda i: store.publish("Concurrent", {"value": i}), range(40)))
    assert sorted(profile.version for profile in profiles) == list(range(1, 41))
    assert store.get("Concurrent").version == 40
    assert store.get("Concurrent").body == next(p.body for p in profiles if p.version == 40)


def test_publish_continues_persisted_version_and_isolates_bodies(store) -> None:
    store.put(Profile(vdom="Default", version=12, body={"nested": {"value": 1}}))
    body = {"nested": {"value": 2}}
    published = store.publish("Default", body)
    assert published.version == 13
    body["nested"]["value"] = 99
    published.body["nested"]["value"] = 88
    assert store.get("Default").body == {"nested": {"value": 2}}
    retrieved = store.get("Default")
    retrieved.body["nested"]["value"] = 77
    listed = store.all()
    listed[0].body["nested"]["value"] = 66
    assert store.get("Default").body == {"nested": {"value": 2}}
