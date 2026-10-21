"""Contract tests every ProfileStore implementation must satisfy.

InMemoryProfileStore runs always; PostgresProfileStore runs when OPENEMS_TEST_DSN
points at a reachable database (see test_store_contract.py for how to spin one up).
"""

from __future__ import annotations

import os

import pytest

from app.models import Profile
from app.stores import InMemoryProfileStore, PostgresProfileStore


def _make_inmemory():
    return InMemoryProfileStore()


def _make_postgres():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set; skipping PostgresProfileStore test")
    store = PostgresProfileStore(dsn)
    store.init_schema()
    with store._conn.cursor() as cur:  # noqa: SLF001 - test-only reset
        cur.execute("TRUNCATE profiles")
    return store


@pytest.fixture(params=[_make_inmemory, _make_postgres], ids=["inmemory", "postgres"])
def store(request):
    return request.param()


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
