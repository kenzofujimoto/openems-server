"""Management parity: guarded accounts, one-time invitations and trusted installer delivery."""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import RegisterRequest
from app.service import EmsService


@pytest.fixture
def harness():
    service, admin, audit = EmsService(), AdminService(), InMemoryAuditLog()
    admin.add_admin("operator", "operator-password")
    admin.add_admin("reader", "reader-password", "viewer")
    client = TestClient(create_app(service, admin_service=admin, audit_log=audit))
    writer = {"Authorization": "Bearer " + admin.issue_token("operator", "admin")}
    reader = {"Authorization": "Bearer " + admin.issue_token("reader", "viewer")}
    return service, admin, audit, client, writer, reader


def test_profile_if_match_prevents_stale_editor_overwrite(harness):
    _, _, _, client, writer, _ = harness
    first = client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": []}}, headers=writer).json()
    update = {"web_filter": {"blocked": ["example.com"]}}
    assert client.post("/api/v1/profiles/Default", json=update, headers={**writer, "If-Match": first["digest"]}).status_code == 200
    stale = client.post("/api/v1/profiles/Default", json={"web_filter": {"blocked": ["stale.example"]}}, headers={**writer, "If-Match": first["digest"]})
    assert stale.status_code == 412
    assert client.get("/api/v1/profiles", headers=writer).json()[0]["body"] == update


def test_accounts_never_expose_hashes_and_protect_self_last_writer_and_superadmin(harness):
    _, admin, _, client, writer, reader = harness
    assert client.get("/api/v1/admins", headers=reader).status_code == 403
    assert client.post("/api/v1/admins", json={"username": "new", "password": "new-password", "role": "admin"}, headers=reader).status_code == 403
    created = client.post("/api/v1/admins", json={"username": "new", "password": "new-password", "role": "admin"}, headers=writer)
    assert created.status_code == 200
    assert "password" not in created.text
    assert client.post("/api/v1/admins", json={"username": "new", "password": "replace-password", "role": "viewer"}, headers=writer).status_code == 409
    assert client.delete("/api/v1/admins/operator", headers=writer).status_code == 409
    assert client.put("/api/v1/admins/new", json={"role": "viewer"}, headers=writer).status_code == 200
    assert client.put("/api/v1/admins/operator", json={"role": "viewer"}, headers=writer).status_code == 409
    admin.add_admin("root", "root-password", "superadmin")
    assert client.delete("/api/v1/admins/root", headers=writer).status_code == 403
    assert client.put("/api/v1/admins/root", json={"password": "changed-password"}, headers=writer).status_code == 403
    assert client.delete("/api/v1/admins/new", headers=writer).status_code == 200
    rows = client.get("/api/v1/admins", headers=writer).json()
    assert {tuple(sorted(row)) for row in rows} == {("role", "username")}


def test_changed_or_deleted_account_invalidates_existing_sessions(harness):
    _, admin, _, client, writer, _ = harness
    client.post("/api/v1/admins", json={"username": "new", "password": "new-password", "role": "admin"}, headers=writer)
    token = admin.issue_token("new", "admin")
    assert client.put("/api/v1/admins/new", json={"password": "changed-password"}, headers=writer).status_code == 200
    assert admin.verify_token(token) is None


def test_invitations_list_only_hash_ids_and_revoke_without_revealing_tokens(harness):
    service, _, audit, client, writer, reader = harness
    created = client.post("/api/v1/enrollment/invitations", json={"vdom": "Default", "max_uses": 2, "ttl_seconds": 3600}, headers=writer)
    token = created.json()["invitation"]
    identity = hashlib.sha256(token.encode()).hexdigest()
    assert client.get("/api/v1/enrollment/invitations", headers=reader).status_code == 403
    listing = client.get("/api/v1/enrollment/invitations", headers=writer)
    assert listing.status_code == 200 and token not in listing.text
    assert listing.json()[0]["id"] == identity and listing.json()[0]["remaining"] == 2
    assert client.delete(f"/api/v1/enrollment/invitations/{identity}", headers=writer).status_code == 200
    assert client.delete(f"/api/v1/enrollment/invitations/{identity}", headers=writer).status_code == 404
    with pytest.raises(ValueError):
        service.register(RegisterRequest(devid="revoked-test", invitation=token))
    assert token not in str(audit.list())


def test_settings_are_read_only_and_installer_is_operator_supplied(harness, tmp_path):
    service, admin, _, client, writer, reader = harness
    settings = client.get("/api/v1/settings", headers=reader)
    assert settings.status_code == 200 and settings.json()["event_retention_days"] == 30
    assert client.get("/api/v1/installers/windows", headers=writer).json()["available"] is False
    artifact = tmp_path / "trusted.msi"
    artifact.write_bytes(b"test-msi-fixture")
    application = create_app(service, admin_service=admin, installer_path=artifact)
    with TestClient(application) as configured:
        metadata = configured.get("/api/v1/installers/windows", headers=writer)
        assert metadata.status_code == 200 and metadata.json()["available"] is True
        assert metadata.json()["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert str(artifact) not in metadata.text
        assert configured.get(metadata.json()["download_url"], headers=reader).status_code == 403
        download = configured.get(metadata.json()["download_url"], headers=writer)
        assert download.content == artifact.read_bytes() and download.headers["cache-control"] == "no-store"
