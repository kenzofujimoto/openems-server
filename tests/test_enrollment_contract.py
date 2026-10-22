"""Enrollment invitations are finite, scoped, expiring and consumed atomically."""

import importlib
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest


@pytest.fixture(params=["memory", "postgres"])
def invitations(request):
    module = importlib.import_module("app.enrollment")
    if request.param == "memory":
        yield module.InMemoryEnrollmentStore()
        return
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not configured")
    store = module.PostgresEnrollmentStore(dsn)
    store.init_schema()
    yield store
    store.close()


def test_invitation_scope_expiry_and_one_time_use(invitations):
    token = secrets.token_urlsafe(32)
    invitations.add(token, "Strict", 1, datetime.now(UTC) + timedelta(minutes=5))
    assert not invitations.consume(token, "Default")
    assert not invitations.consume("unknown", "Strict")
    assert invitations.consume(token, "Strict")
    assert not invitations.consume(token, "Strict")
    # Restart/bootstrap cannot replenish an existing invitation.
    invitations.add(token, "Strict", 99, datetime.now(UTC) + timedelta(days=1))
    assert not invitations.consume(token, "Strict")
    expired = secrets.token_urlsafe(32)
    invitations.add(expired, "Strict", 1, datetime.now(UTC) - timedelta(seconds=1))
    assert not invitations.consume(expired, "Strict")


def test_concurrent_consumers_cannot_exceed_limit(invitations):
    token = secrets.token_urlsafe(32)
    invitations.add(token, "Default", 3, datetime.now(UTC) + timedelta(minutes=5))
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: invitations.consume(token, "Default"), range(20)))
    assert sum(outcomes) == 3
