"""Management parity: guarded accounts, one-time invitations and trusted installer delivery."""
from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import RegisterRequest
from app.service import EmsService, RegistrationError


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
    with pytest.raises(RegistrationError):
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


def test_installer_bundle_contains_a_scoped_one_time_invitation_without_audit_disclosure(harness, tmp_path):
    service, admin, audit, _, writer, _ = harness
    artifact = tmp_path / "trusted.msi"
    artifact.write_bytes(b"test-msi")
    app = create_app(service, admin_service=admin, audit_log=audit, installer_path=artifact,
                     public_base_url="https://ems.example.com")
    with TestClient(app) as client:
        response = client.post("/api/v1/installers/windows/bundle", headers=writer,
                               json={"vdom": "Default", "max_uses": 1, "ttl_seconds": 3600})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert set(archive.namelist()) == {"openems-agent.msi", "install.ps1", "README.txt"}
            assert archive.read("openems-agent.msi") == b"test-msi"
            script = archive.read("install.ps1").decode("utf-8-sig")
        assert "$server = 'https://ems.example.com'" in script
        token = script.split("$invitation = '", 1)[1].split("'", 1)[0]
        assert token not in str(audit.list())
        service.register(RegisterRequest(devid="bundled", invitation=token))
        with pytest.raises(RegistrationError):
            service.register(RegisterRequest(devid="second", invitation=token))


@pytest.mark.parametrize("base_url", [None, "http://public.example", "https://user:secret@ems.example", "https://ems.example/?secret=yes"])
def test_installer_bundle_refuses_missing_or_unsafe_configuration(harness, tmp_path, base_url):
    service, admin, _, _, writer, _ = harness
    artifact = tmp_path / "trusted.msi"
    artifact.write_bytes(b"test-msi")
    with TestClient(create_app(service, admin_service=admin, installer_path=artifact, public_base_url=base_url)) as client:
        response = client.post("/api/v1/installers/windows/bundle", headers=writer,
                               json={"vdom": "Default", "max_uses": 1, "ttl_seconds": 3600})
        assert response.status_code == 503
        assert service.list_invitations() == []


def test_account_mutations_keep_the_csrf_and_role_guards(harness):
    _, admin, _, client, writer, _ = harness
    session = admin.issue_session("operator", "admin")
    client.cookies.set("openems_session", session["token"])
    payload = {"username": "cookie-account", "password": "test-password", "role": "viewer"}
    assert client.post("/api/v1/admins", json=payload).status_code == 403
    assert client.post("/api/v1/admins", json=payload, headers={"X-CSRF-Token": session["csrf_token"]}).status_code == 200
    assert client.post("/api/v1/admins", json={**payload, "role": "superadmin"}, headers=writer).status_code == 422


def test_account_and_installer_missing_resources_return_explicit_errors(harness, tmp_path):
    service, admin, _, client, writer, _ = harness
    assert client.put("/api/v1/admins/missing", json={"role": "viewer"}, headers=writer).status_code == 404
    assert client.delete("/api/v1/admins/missing", headers=writer).status_code == 404
    assert client.post("/api/v1/admins", json={"username": "bad/name", "password": "test-password", "role": "viewer"}, headers=writer).status_code == 422
    assert client.get("/api/v1/installers/windows/download", headers=writer).status_code == 404
    not_msi = tmp_path / "untrusted.exe"
    not_msi.write_bytes(b"not-an-installer")
    for artifact in (not_msi, tmp_path / "missing.msi"):
        with TestClient(create_app(service, admin_service=admin, installer_path=artifact)) as configured:
            assert configured.get("/api/v1/installers/windows", headers=writer).json() == {"available": False}


def test_bundle_rejects_quoted_group_and_does_not_leave_an_invitation_on_read_failure(harness, tmp_path, monkeypatch):
    service, admin, _, _, writer, _ = harness
    artifact = tmp_path / "trusted.msi"
    artifact.write_bytes(b"test-msi")
    app = create_app(service, admin_service=admin, installer_path=artifact, public_base_url="https://ems.example.com")
    with TestClient(app) as client:
        payload = {"vdom": 'quoted"group', "max_uses": 1, "ttl_seconds": 3600}
        assert client.post("/api/v1/installers/windows/bundle", json=payload, headers=writer).status_code == 422
        assert service.list_invitations() == []

        def unavailable(*args, **kwargs):
            raise PermissionError("test artifact became unreadable")

        monkeypatch.setattr(zipfile.ZipFile, "write", unavailable)
        response = client.post("/api/v1/installers/windows/bundle", json={**payload, "vdom": "Default"}, headers=writer)
        assert response.status_code == 503 and service.list_invitations() == []


def test_installer_metadata_handles_an_unreadable_file_without_disclosing_its_path(harness, tmp_path, monkeypatch):
    service, admin, _, _, writer, _ = harness
    artifact = tmp_path / "trusted.msi"
    artifact.write_bytes(b"test-msi")
    app = create_app(service, admin_service=admin, installer_path=artifact)
    original_open = type(artifact).open

    def inaccessible(path, *args, **kwargs):
        if path == artifact:
            raise PermissionError("sensitive operator path")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(type(artifact), "open", inaccessible)
    with TestClient(app) as client:
        response = client.get("/api/v1/installers/windows", headers=writer)
        assert response.status_code == 503 and str(artifact) not in response.text
