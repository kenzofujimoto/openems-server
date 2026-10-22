"""Tests for admin authentication (password hashing, tokens, API gating)."""

from __future__ import annotations

import pytest

from app.auth import AdminService, hash_password, verify_password

# --- password hashing ---------------------------------------------------


def test_password_hash_roundtrip() -> None:
    h = hash_password("s3cret")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret", h)
    assert not verify_password("wrong", h)


def test_verify_handles_garbage() -> None:
    assert not verify_password("x", "not-a-hash")


# --- token issue / verify ----------------------------------------------


def test_token_issue_and_verify() -> None:
    svc = AdminService(secret="unit-test-secret")
    svc.add_admin("admin", "pw")
    token = svc.issue_token("admin", "admin")
    claims = svc.verify_token(token)
    assert claims == {"username": "admin", "role": "admin"}


def test_expired_token_rejected() -> None:
    svc = AdminService(secret="s")
    svc.add_admin("admin", "pw")
    token = svc.issue_token("admin", "admin", ttl_seconds=-1)
    assert svc.verify_token(token) is None


def test_tampered_token_rejected() -> None:
    svc = AdminService(secret="s")
    svc.add_admin("admin", "pw")
    token = svc.issue_token("admin", "admin")
    raw, sig = token.split(".", 1)
    assert svc.verify_token(raw + "." + ("0" * len(sig))) is None


def test_token_from_other_secret_rejected() -> None:
    a, b = AdminService(secret="a"), AdminService(secret="b")
    a.add_admin("admin", "pw")
    assert b.verify_token(a.issue_token("admin", "admin")) is None


def test_authenticate() -> None:
    svc = AdminService()
    svc.add_admin("kenzo", "pw", role="superadmin")
    assert svc.authenticate("kenzo", "pw") == "superadmin"
    assert svc.authenticate("kenzo", "nope") is None
    assert svc.authenticate("ghost", "pw") is None


# --- API gating ---------------------------------------------------------


@pytest.fixture
def secured():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from app.api import create_app
    from app.service import EmsService

    admins = AdminService(secret="test")
    admins.add_admin("admin", "pw")
    return TestClient(
        create_app(
            EmsService(valid_invitations={"auth-test-invite"}), admin_service=admins
        )
    )


def test_protected_route_requires_token(secured) -> None:
    assert secured.get("/api/v1/endpoints/count").status_code == 401


def test_login_bad_credentials(secured) -> None:
    assert (
        secured.post(
            "/api/v1/auth/login", json={"username": "admin", "password": "nope"}
        ).status_code
        == 401
    )


def test_login_then_access(secured) -> None:
    token = secured.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "pw"}
    ).json()["token"]
    r = secured.get(
        "/api/v1/endpoints/count", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200 and r.json() == {"count": 0}


def test_endpoint_channel_not_gated(secured) -> None:
    # device registration must work without an admin token
    r = secured.post(
        "/fct/api/public/v1/register/",
        json={"devid": "DEV-1", "invitation": "auth-test-invite"},
    )
    assert r.status_code == 200
