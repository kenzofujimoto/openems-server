"""Contract tests for RuleStore and AdminStore (in-memory always; Postgres when
OPENEMS_TEST_DSN is set)."""

from __future__ import annotations

import os

import pytest

from app.models import AssignmentRule, Condition
from app.stores import (
    InMemoryAdminStore,
    InMemoryRuleStore,
    PostgresAdminStore,
    PostgresRuleStore,
)


def _dsn_or_skip():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    return dsn


# --- RuleStore ----------------------------------------------------------

def _make_rule_inmemory():
    return InMemoryRuleStore()


def _make_rule_postgres():
    store = PostgresRuleStore(_dsn_or_skip())
    store.init_schema()
    with store._conn.cursor() as cur:
        cur.execute("TRUNCATE assignment_rules")
    return store


@pytest.fixture(params=[_make_rule_inmemory, _make_rule_postgres], ids=["inmemory", "postgres"])
def rule_store(request):
    return request.param()


def _rule(rid="r1", vdom="A", prio=10):
    return AssignmentRule(
        id=rid, target_vdom=vdom, priority=prio,
        conditions=[Condition("os", "contains", "Windows")],
    )


def test_rule_add_and_all_preserves_conditions(rule_store) -> None:
    rule_store.add(_rule())
    rules = rule_store.all()
    assert len(rules) == 1
    assert rules[0].conditions[0].value == "Windows"
    assert rules[0].priority == 10


def test_rule_add_upserts_by_id(rule_store) -> None:
    rule_store.add(_rule(vdom="A"))
    rule_store.add(_rule(vdom="B"))
    assert len(rule_store.all()) == 1
    assert rule_store.all()[0].target_vdom == "B"


def test_rule_remove(rule_store) -> None:
    rule_store.add(_rule())
    assert rule_store.remove("r1") is True
    assert rule_store.all() == []
    assert rule_store.remove("r1") is False


# --- AdminStore ---------------------------------------------------------

def _make_admin_inmemory():
    return InMemoryAdminStore()


def _make_admin_postgres():
    store = PostgresAdminStore(_dsn_or_skip())
    store.init_schema()
    with store._conn.cursor() as cur:
        cur.execute("TRUNCATE admins")
    return store


@pytest.fixture(params=[_make_admin_inmemory, _make_admin_postgres], ids=["inmemory", "postgres"])
def admin_store(request):
    return request.param()


def test_admin_missing_and_has_any(admin_store) -> None:
    assert admin_store.get("x") is None
    assert admin_store.has_any() is False
    admin_store.put("kenzo", "hash1", "admin")
    assert admin_store.has_any() is True


def test_admin_put_get(admin_store) -> None:
    admin_store.put("kenzo", "hash1", "superadmin")
    assert admin_store.get("kenzo") == ("hash1", "superadmin")


def test_admin_put_overwrites(admin_store) -> None:
    admin_store.put("kenzo", "hash1", "admin")
    admin_store.put("kenzo", "hash2", "superadmin")
    assert admin_store.get("kenzo") == ("hash2", "superadmin")
