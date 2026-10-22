"""Behavioral security contracts for admin sessions and login limits."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets

import pytest

from app.auth import AdminService
from app.stores import InMemoryAdminStore


@pytest.fixture
def admin():
    service = AdminService(secret="session-test-secret")
    service.add_admin("alice", "correct-password")
    return service


def test_unregistered_user_cannot_receive_session():
    with pytest.raises(ValueError):
        AdminService().issue_token("unknown", "admin")


def test_cannot_issue_session_with_another_role(admin):
    with pytest.raises(ValueError):
        admin.issue_token("alice", "superadmin")


@pytest.mark.parametrize("role", ["owner", "", "ADMIN"])
def test_unknown_roles_are_rejected(admin, role):
    with pytest.raises(ValueError):
        admin.add_admin("outsider", "password", role)


@pytest.mark.parametrize(
    "role,action,allowed",
    [("viewer", "read", True), ("viewer", "write", False),
     ("viewer", "manage_idp", False), ("admin", "write", True),
     ("admin", "manage_idp", True), ("superadmin", "manage_idp", True),
     ("other", "read", False), ("admin", "unknown", False)],
)
def test_permissions_are_explicit_and_fail_closed(admin, role, action, allowed):
    assert admin.is_allowed(role, action) is allowed


def test_session_csrf_is_unique_and_bound_to_token(admin):
    first = admin.issue_session("alice", "admin")
    second = admin.issue_session("alice", "admin")
    assert first["token"] != second["token"]
    assert first["csrf_token"] != second["csrf_token"]
    assert admin.csrf_for_token(first["token"]) == first["csrf_token"]
    assert admin.verify_csrf(first["token"], first["csrf_token"])
    assert not admin.verify_csrf(first["token"], second["csrf_token"])
    assert not admin.verify_csrf(first["token"], "")


def test_logout_revokes_only_the_selected_session(admin):
    first = admin.issue_token("alice", "admin")
    second = admin.issue_token("alice", "admin")
    assert admin.revoke_token(first)
    assert admin.verify_token(first) is None
    assert admin.csrf_for_token(first) is None
    assert admin.verify_token(second) == {"username": "alice", "role": "admin"}
    assert not admin.revoke_token(first)


def test_expiry_boundary_is_rejected(admin, monkeypatch):
    monkeypatch.setattr("app.auth.time.time", lambda: 1_000)
    token = admin.issue_token("alice", "admin", ttl_seconds=10)
    monkeypatch.setattr("app.auth.time.time", lambda: 1_010)
    assert admin.verify_token(token) is None


@pytest.mark.parametrize("change", ["password", "role", "removed"])
def test_live_account_changes_invalidate_existing_sessions(admin, change):
    token = admin.issue_token("alice", "admin")
    if change == "password":
        admin.add_admin("alice", "new-password")
    elif change == "role":
        old_hash, _ = admin._store.get("alice")
        admin._store.put("alice", old_hash, "viewer")
    else:
        admin._store._admins.pop("alice")
    assert admin.verify_token(token) is None


@pytest.mark.parametrize("payload", [[], None, {"exp": "broken"}, {"exp": True},
                                    {"sid": [], "exp": 99999999999}])
def test_signed_malformed_claims_fail_closed_without_crashing(admin, payload):
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(b"session-test-secret", raw.encode(), hashlib.sha256).hexdigest()
    assert admin.verify_token(f"{raw}.{signature}") is None


@pytest.mark.parametrize("token", ["not-a-token", "é.sig", ".", "x." + "x" * 100000],
                         ids=["no-separator", "non-ascii", "empty", "oversized"])
def test_malformed_tokens_are_rejected(admin, token):
    assert admin.verify_token(token) is None


def test_login_rate_limit_is_shared_between_workers(monkeypatch):
    from app.auth import LoginRateLimited
    from app.sessions import InMemorySessionStore

    account_store, session_store = InMemoryAdminStore(), InMemorySessionStore()
    workers = [AdminService(store=account_store, session_store=session_store,
                            login_max_attempts=2, login_window_seconds=60)
               for _ in range(2)]
    workers[0].add_admin("alice", "correct")
    monkeypatch.setattr("app.auth.time.time", lambda: 1_000)
    assert workers[0].authenticate_with_rate_limit("alice", "wrong", "127.0.0.1") is None
    assert workers[1].authenticate_with_rate_limit("alice", "wrong", "127.0.0.1") is None
    with pytest.raises(LoginRateLimited) as error:
        workers[0].authenticate_with_rate_limit("alice", "correct", "127.0.0.1")
    assert 0 < error.value.retry_after <= 60
    # A separate remote address is independent, while a spoofed header is never an input.
    assert workers[0].authenticate_with_rate_limit("alice", "correct", "127.0.0.2") == "admin"
    monkeypatch.setattr("app.auth.time.time", lambda: 1_061)
    assert workers[0].authenticate_with_rate_limit("alice", "correct", "127.0.0.1") == "admin"


def test_successful_login_resets_its_attempt_bucket(admin):
    for _ in range(8):
        assert admin.authenticate_with_rate_limit("alice", "wrong", "127.0.0.1") is None
        assert admin.authenticate_with_rate_limit("alice", "correct-password", "127.0.0.1") == "admin"


@pytest.fixture(params=["memory", "postgres"])
def shared_sessions(request):
    from app.sessions import InMemorySessionStore, PostgresSessionStore

    if request.param == "memory":
        store = InMemorySessionStore()
        yield store, store
        return
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    first, second = PostgresSessionStore(dsn), PostgresSessionStore(dsn)
    first.init_schema()
    second.init_schema()
    try:
        yield first, second
    finally:
        first.close()
        second.close()


def test_shared_session_revocation_and_credential_changes(shared_sessions):
    first_store, second_store = shared_sessions
    accounts = InMemoryAdminStore()
    first = AdminService(secret="shared-test-secret", store=accounts, session_store=first_store)
    second = AdminService(secret="shared-test-secret", store=accounts, session_store=second_store)
    username = f"user-{secrets.token_hex(8)}"
    first.add_admin(username, "password")
    token = first.issue_token(username, "admin")
    assert second.verify_token(token) == {"username": username, "role": "admin"}
    assert second.revoke_token(token)
    assert first.verify_token(token) is None
    token = first.issue_token(username, "admin")
    second.add_admin(username, "replacement")
    assert first.verify_token(token) is None


def test_shared_login_limit_is_atomic(shared_sessions):
    first, second = shared_sessions
    key = f"test-{secrets.token_hex(8)}"
    assert first.consume_login_attempt(key, now=1_000, window_seconds=60, max_attempts=2) == 0
    assert second.consume_login_attempt(key, now=1_001, window_seconds=60, max_attempts=2) == 0
    assert first.consume_login_attempt(key, now=1_002, window_seconds=60, max_attempts=2) == 58
    first.reset_login(key)
    assert second.consume_login_attempt(key, now=1_003, window_seconds=60, max_attempts=2) == 0
