"""HTTP security boundaries exercised through the complete ASGI application."""

from __future__ import annotations

import base64
import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from app.api import build, create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.service import EmsService
from app.sessions import InMemorySessionStore

_ENVIRONMENT = (
    "OPENEMS_ADMIN",
    "OPENEMS_RECORD",
    "OPENEMS_LAB_MODE",
    "OPENEMS_DATABASE_URL",
    "OPENEMS_SESSION_SECRET",
    "OPENEMS_BASE_URL",
    "OPENEMS_REDIS_URL",
    "OPENEMS_ENROLLMENT_TOKEN",
    "OPENEMS_ENROLLMENT_VDOM",
    "OPENEMS_ENROLLMENT_USES",
)


@pytest.fixture(autouse=True)
def isolated_application_environment(monkeypatch):
    for key in _ENVIRONMENT:
        monkeypatch.delenv(key, raising=False)


@dataclass
class HttpHarness:
    client: TestClient
    service: EmsService
    admins: AdminService
    audit: InMemoryAuditLog
    admin_headers: dict[str, str]
    viewer_headers: dict[str, str]

    def enroll(self, *, devid: str = "test-pc", vdom: str = "Default") -> dict:
        response = self.client.post(
            "/fct/api/public/v1/register/",
            json={
                "devid": devid,
                "vdom": vdom,
                "invitation": self.service.create_invitation(vdom),
            },
        )
        assert response.status_code == 200
        return response.json()


@pytest.fixture
def http():
    admins = AdminService(secret=secrets.token_bytes(32))
    admins.add_admin("operator", "operator-password")
    admins.add_admin("reader", "reader-password", "viewer")
    service, audit = EmsService(), InMemoryAuditLog()
    app = create_app(service, admin_service=admins, audit_log=audit)
    with TestClient(app, base_url="https://testserver") as client:
        yield HttpHarness(
            client,
            service,
            admins,
            audit,
            {"Authorization": "Bearer " + admins.issue_token("operator", "admin")},
            {"Authorization": "Bearer " + admins.issue_token("reader", "viewer")},
        )


@pytest.fixture(scope="module")
def idp_metadata():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    encoded = base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)
    ).decode()
    return (
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" '
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
        + encoded
        + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"
        '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        'Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor>'
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/endpoints/count",
        "/api/v1/profiles",
        "/api/v1/assignment_rules",
        "/api/v1/audit",
    ],
)
def test_viewer_can_read_management(http, path):
    assert http.client.get(path, headers=http.viewer_headers).status_code == 200


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("POST", "/api/v1/profiles/Default", {}),
        ("POST", "/api/v1/assignment_rules", {"id": "r", "target_vdom": "Default"}),
        ("DELETE", "/api/v1/assignment_rules/r", None),
        ("POST", "/api/v1/enrollment/invitations", {}),
        ("POST", "/api/v1/endpoints/revoke", {"devid": "test-pc"}),
        ("POST", "/api/v1/endpoints/credentials/rotate", {"devid": "test-pc"}),
        ("POST", "/fct_saml/parse_remote_metadata", {"metadata": "<invalid/>"}),
    ],
)
def test_viewer_cannot_perform_privileged_actions(http, method, path, payload):
    assert (
        http.client.request(
            method, path, headers=http.viewer_headers, json=payload
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/profiles/Default",
        "/api/v1/profiles/Default/",
        "/api/v1/%70rofiles/Default",
        "/api/v1//profiles/Default",
        "/fct_saml/parse_remote_metadata",
        "/fct_saml/parse_remote_metadata/",
        "/fct_saml/%70arse_remote_metadata",
        "/fct_saml//parse_remote_metadata",
    ],
)
def test_route_aliases_cannot_bypass_management_authentication(
    http, path, idp_metadata
):
    response = http.client.post(
        path, json={"prefix": "attack", "metadata": idp_metadata}
    )
    assert response.status_code in {401, 403, 404}
    assert http.service.list_profiles() == []
    assert (
        http.client.get(
            "/fct_saml/login?prefix=attack", follow_redirects=False
        ).status_code
        == 404
    )


def test_idp_configuration_requires_admin_and_is_audited(http, idp_metadata):
    response = http.client.post(
        "/fct_saml/parse_remote_metadata",
        headers=http.admin_headers,
        json={"prefix": "trusted", "metadata": idp_metadata},
    )
    assert response.status_code == 200
    assert (
        http.client.get(
            "/fct_saml/login?prefix=trusted", follow_redirects=False
        ).status_code
        == 302
    )
    entries = http.client.get("/api/v1/audit", headers=http.admin_headers).json()
    assert any(
        entry["actor"] == "operator"
        and entry["action"] == "idp.configure"
        and entry["target"] == "trusted"
        for entry in entries
    )
    assert idp_metadata not in json.dumps(entries)


def test_cookie_session_cannot_mutate_without_its_own_csrf_and_logout_revokes(http):
    login = http.client.post(
        "/api/v1/auth/login", json={"username": "reader", "password": "reader-password"}
    )
    cookie = login.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert login.headers["cache-control"] == "no-store"
    assert http.client.get("/api/v1/auth/session").json()["role"] == "viewer"
    assert http.client.post("/api/v1/auth/logout").status_code == 403
    assert (
        http.client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": "forged"}
        ).status_code
        == 403
    )
    csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
    assert http.client.post("/api/v1/auth/logout", headers=csrf).status_code == 200
    assert http.client.get("/api/v1/auth/session").status_code == 401
    assert (
        http.client.get(
            "/api/v1/auth/session",
            headers={"Authorization": "Bearer " + login.json()["token"]},
        ).status_code
        == 401
    )


def test_cross_session_csrf_and_invalid_bearer_do_not_fall_back_to_valid_cookie(http):
    logged = http.client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "operator-password"},
    ).json()
    other = http.admins.issue_session("operator", "admin")
    assert (
        http.client.post(
            "/api/v1/profiles/Default",
            json={},
            headers={"X-CSRF-Token": other["csrf_token"]},
        ).status_code
        == 403
    )
    assert (
        http.client.post(
            "/api/v1/profiles/Default",
            json={},
            headers={
                "Authorization": "Bearer invalid",
                "X-CSRF-Token": logged["csrf_token"],
            },
        ).status_code
        == 401
    )
    assert (
        http.client.post(
            "/api/v1/profiles/Default",
            json={},
            headers={"X-CSRF-Token": logged["csrf_token"]},
        ).status_code
        == 200
    )


def test_non_ascii_token_is_rejected_without_server_error(http):
    # HTTP header values can contain Latin-1 octets; ASGI preserves them.
    response = http.client.get(
        "/api/v1/endpoints/count", headers={b"authorization": b"Bearer \xe9.signature"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "path,method",
    [("/api/v1/endpoints/count", "GET"), ("/api/v1/profiles/Default", "POST")],
)
def test_authentication_errors_are_not_cached(http, path, method):
    response = http.client.request(method, path, json={} if method == "POST" else None)
    assert response.status_code == 401
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1", "localhost", "testclient"])
def test_explicit_lab_mode_only_opens_for_loopback_peers(peer):
    app = create_app(lab_mode=True)

    async def from_peer(scope, receive, send):
        await app({**scope, "client": (peer, 12345)}, receive, send)

    with TestClient(from_peer) as client:
        assert client.get("/api/v1/endpoints/count").status_code == 200
        assert client.get("/api/v1/auth/session").status_code == 401
        assert (
            client.post(
                "/fct/api/public/v1/register/", json={"devid": "lab-pc"}
            ).status_code
            == 200
        )


@pytest.mark.parametrize("peer", ["198.51.100.12", "192.168.1.7", "", None])
def test_lab_remote_peer_cannot_spoof_loopback_with_host_or_forwarded_headers(peer):
    app = create_app(lab_mode=True)

    async def from_peer(scope, receive, send):
        await app(
            {**scope, "client": (peer, 12345) if peer is not None else None},
            receive,
            send,
        )

    with TestClient(from_peer) as client:
        response = client.get(
            "/api/v1/endpoints/count",
            headers={
                "Host": "localhost",
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
            },
        )
        assert response.status_code == 403


def test_login_rate_limit_uses_transport_peer_and_emits_audit_events():
    admins = AdminService(login_max_attempts=2)
    admins.add_admin("operator", "password")
    audit = InMemoryAuditLog()
    app = create_app(admin_service=admins, audit_log=audit)
    with TestClient(app) as client:
        for suffix in ("1", "2"):
            response = client.post(
                "/api/v1/auth/login",
                headers={"X-Forwarded-For": "203.0.113." + suffix},
                json={"username": "operator", "password": "wrong-secret"},
            )
            assert response.status_code == 401
        limited = client.post(
            "/api/v1/auth/login",
            headers={"X-Forwarded-For": "127.0.0.1"},
            json={"username": "operator", "password": "password"},
        )
        assert limited.status_code == 429
        assert 0 < int(limited.headers["retry-after"]) <= 300
    entries = audit.list(10)
    assert [entry.action for entry in reversed(entries)] == [
        "auth.failure",
        "auth.failure",
        "auth.rate_limited",
    ]
    assert "wrong-secret" not in repr(entries)


def test_login_session_capacity_failure_is_generic():
    admins = AdminService(session_store=InMemorySessionStore(max_sessions=0))
    admins.add_admin("operator", "private-password")
    with TestClient(create_app(admin_service=admins)) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "operator", "password": "private-password"},
        )
    assert response.status_code == 503
    assert "private-password" not in response.text


@pytest.mark.parametrize("content_length", [None, "0", "1"])
def test_streamed_body_limit_counts_bytes_instead_of_trusting_content_length(
    http, content_length
):
    headers = {} if content_length is None else {"Content-Length": content_length}

    def chunks():
        yield b'{"devid":"'
        for _ in range(17):
            yield b"x" * 65536
        yield b'"}'

    response = http.client.post(
        "/fct/api/public/v1/register/", headers=headers, content=chunks()
    )
    assert response.status_code == 413
    assert http.service.count() == 0


@pytest.mark.parametrize("content_length", ["-1", "not-an-integer"])
def test_invalid_declared_lengths_are_rejected_before_parsing(http, content_length):
    response = http.client.post(
        "/fct/api/public/v1/register/",
        headers={"Content-Length": content_length},
        content=b"{}",
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "path,payload",
    [
        (
            "/api/v1/auth/login",
            {"username": "operator", "password": "sensitive-marker-" * 300},
        ),
        (
            "/fct/api/public/v1/register/",
            {"devid": "pc", "invitation": ["sensitive-marker"]},
        ),
        (
            "/fct/api/public/v1/register/",
            {"devid": "pc", "key": {"value": "sensitive-marker"}},
        ),
    ],
)
def test_schema_errors_do_not_echo_passwords_or_device_secrets(http, path, payload):
    response = http.client.post(path, json=payload)
    assert response.status_code == 422
    assert "sensitive-marker" not in response.text


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "os", "op": "in", "value": "Windows"},
        {"field": "os", "op": "equals", "value": ["Windows"]},
        {"field": "host_tag", "op": "equals", "value": "safe"},
        {"field": "os", "op": "has_tag", "value": "safe"},
        {"field": "os", "op": "in", "value": ["x"] * 257},
        {"field": "os", "op": "equals", "value": "x" * 513},
    ],
)
def test_invalid_rule_types_and_operators_are_rejected(http, condition):
    response = http.client.post(
        "/api/v1/assignment_rules",
        headers=http.admin_headers,
        json={"id": "rule", "target_vdom": "Default", "conditions": [condition]},
    )
    assert response.status_code == 422
    assert http.service.list_rules() == []


def test_tag_validation_and_deduplication_preserve_state(http):
    endpoint = http.enroll()
    headers = {"Authorization": "Bearer " + endpoint["device_token"]}
    identity = {"client_id": endpoint["client_id"]}
    for tags in ([""], ["x" * 257], [1], ["x"] * 257):
        response = http.client.post(
            "/fct/api/public/v1/host_tags/",
            headers=headers,
            json={**identity, "tags": tags},
        )
        assert response.status_code == 422
    response = http.client.post(
        "/fct/api/public/v1/host_tags/",
        headers=headers,
        json={**identity, "tags": ["safe", "safe", "managed"]},
    )
    assert response.json()["host_tags"] == ["safe", "managed"]


def test_unassigned_policy_has_no_applicable_ack_and_cross_group_fetch_is_denied(http):
    endpoint = http.enroll()
    headers = {"Authorization": "Bearer " + endpoint["device_token"]}
    identity = {"client_id": endpoint["client_id"]}
    assigned = http.client.get(
        "/fct/api/public/v1/config/assigned/", params=identity, headers=headers
    )
    assert assigned.json() == {
        "vdom": "Default",
        "version": 0,
        "digest": "",
        "body": None,
        "unassigned": True,
    }
    ack = http.client.post(
        "/fct/api/public/v1/config/ack/",
        headers=headers,
        json={**identity, "vdom": "Default", "version": 0, "digest": ""},
    )
    assert ack.status_code == 409
    assert endpoint["device_token"] not in ack.text
    assert (
        http.client.post(
            "/fct/api/public/v1/config/ack/",
            headers=headers,
            json={**identity, "version": 1},
        ).status_code
        == 422
    )
    assert (
        http.client.get(
            "/fct/api/public/v1/config/",
            params={**identity, "vdom": "Default"},
            headers=headers,
        ).status_code
        == 404
    )
    http.service.set_profile("Other", {})
    assert (
        http.client.get(
            "/fct/api/public/v1/config/",
            params={**identity, "vdom": "Other"},
            headers=headers,
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/endpoints/detail?devid=missing",
        "/api/v1/report/fct/host_tags?devid=missing",
    ],
)
def test_unknown_devices_return_generic_errors(http, path):
    response = http.client.get(path, headers=http.admin_headers)
    assert response.status_code == 404
    assert response.json() == {"detail": "unknown endpoint"}


def test_revoked_device_cannot_be_rotated_and_admin_cannot_rotate_unknown_device(http):
    http.enroll()
    assert (
        http.client.post(
            "/api/v1/endpoints/revoke",
            headers=http.admin_headers,
            json={"devid": "test-pc"},
        ).status_code
        == 200
    )
    assert (
        http.client.post(
            "/api/v1/endpoints/credentials/rotate",
            headers=http.admin_headers,
            json={"devid": "test-pc"},
        ).status_code
        == 409
    )
    assert (
        http.client.post(
            "/api/v1/endpoints/credentials/rotate",
            headers=http.admin_headers,
            json={"devid": "missing"},
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "relative",
        "ftp://ems.example",
        "http://ems.example",
        "https://user:password@ems.example",
    ],
)
def test_build_rejects_unsafe_base_urls(monkeypatch, base_url):
    monkeypatch.setenv("OPENEMS_BASE_URL", base_url)
    with pytest.raises(ValueError, match="OPENEMS_BASE_URL"):
        build()


@pytest.mark.parametrize("secret", [None, "short"])
def test_persistent_build_requires_explicit_strong_session_secret(monkeypatch, secret):
    monkeypatch.setenv("OPENEMS_DATABASE_URL", "postgresql://unused/unused")
    if secret is not None:
        monkeypatch.setenv("OPENEMS_SESSION_SECRET", secret)
    with pytest.raises(ValueError, match="OPENEMS_SESSION_SECRET"):
        build()


def test_build_rejects_short_enrollment_token_without_exposing_it(monkeypatch):
    monkeypatch.setenv("OPENEMS_ENROLLMENT_TOKEN", "short-sensitive-token")
    with pytest.raises(ValueError, match="OPENEMS_ENROLLMENT_TOKEN") as error:
        build()
    assert "short-sensitive-token" not in str(error.value)


def test_malformed_bootstrap_is_rejected_and_existing_admin_is_preserved(monkeypatch):
    monkeypatch.setenv("OPENEMS_ADMIN", "invalid-bootstrap")
    with pytest.raises(ValueError, match="OPENEMS_ADMIN"):
        create_app()
    admins = AdminService()
    admins.add_admin("existing", "existing-password")
    monkeypatch.setenv("OPENEMS_ADMIN", "existing:replacement-password")
    with TestClient(create_app(admin_service=admins)) as client:
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"username": "existing", "password": "replacement-password"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"username": "existing", "password": "existing-password"},
            ).status_code
            == 200
        )


@contextmanager
def _isolated_postgres_schema(dsn: str) -> Iterator[str]:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    schema = "http_security_" + secrets.token_hex(12)
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        try:
            yield make_conninfo(dsn, options="-csearch_path=" + schema)
        finally:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )


def test_build_shares_postgres_sessions_and_redis_delivery_across_workers(monkeypatch):
    dsn, redis_url = (
        os.environ.get("OPENEMS_TEST_DSN"),
        os.environ.get("OPENEMS_TEST_REDIS"),
    )
    if not dsn or not redis_url:
        pytest.skip("OPENEMS_TEST_DSN and OPENEMS_TEST_REDIS are required")
    with _isolated_postgres_schema(dsn) as isolated_dsn:
        monkeypatch.setenv("OPENEMS_DATABASE_URL", isolated_dsn)
        monkeypatch.setenv("OPENEMS_REDIS_URL", redis_url)
        monkeypatch.setenv("OPENEMS_SESSION_SECRET", secrets.token_urlsafe(40))
        monkeypatch.setenv("OPENEMS_BASE_URL", "https://testserver")
        monkeypatch.setenv("OPENEMS_ADMIN", "bootstrap:bootstrap-password")
        monkeypatch.setenv("OPENEMS_ENROLLMENT_TOKEN", secrets.token_urlsafe(40))
        first_app = build()
        first_client = TestClient(first_app, base_url="https://testserver")
        with first_client as first:
            logged = first.post(
                "/api/v1/auth/login",
                json={"username": "bootstrap", "password": "bootstrap-password"},
            ).json()
            bearer = {"Authorization": "Bearer " + logged["token"]}
            monkeypatch.setenv("OPENEMS_ADMIN", "bootstrap:must-not-reset-password")
            second_app = build()
            with TestClient(second_app, base_url="https://testserver") as second:
                assert (
                    second.get("/api/v1/auth/session", headers=bearer).status_code
                    == 200
                )
                registered = first.post(
                    "/fct/api/public/v1/register/",
                    json={
                        "devid": "persistent-pc",
                        "invitation": os.environ["OPENEMS_ENROLLMENT_TOKEN"],
                    },
                )
                assert registered.status_code == 200
                endpoint = registered.json()
                assert (
                    first.post(
                        "/api/v1/profiles/Default", json={}, headers=bearer
                    ).status_code
                    == 200
                )
                messages = second.post(
                    "/fct/api/public/v1/messages/pull/",
                    headers={"Authorization": "Bearer " + endpoint["device_token"]},
                    json={"client_id": endpoint["client_id"]},
                )
                assert messages.status_code == 200
                assert messages.json()["messages"][0]["type"] == "config_update"
                assert (
                    first.post("/api/v1/auth/logout", headers=bearer).status_code == 200
                )
                assert (
                    second.get("/api/v1/auth/session", headers=bearer).status_code
                    == 401
                )
