"""Device enrollment, policy identity and authenticated HTTP contracts."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.auth import AdminService
from app.models import AssignmentRule, RegisterRequest
from app.service import EmsService, RegistrationError


@pytest.fixture
def secured():
    admins = AdminService(secret="unit-test-only")
    admins.add_admin("operator", "test-password")
    service = EmsService(require_invitation=True, valid_invitations={"test-invite"})
    client = TestClient(create_app(service, admin_service=admins))
    token = client.post("/api/v1/auth/login", json={"username": "operator", "password": "test-password"}).json()["token"]
    return client, service, {"Authorization": f"Bearer {token}"}


def enroll(client):
    response = client.post("/fct/api/public/v1/register/", json={"devid": "pc", "invitation": "test-invite"})
    assert response.status_code == 200
    return response.json()


def test_management_is_closed_without_administrator():
    client = TestClient(create_app())
    assert client.get("/api/v1/endpoints/count").status_code == 401
    assert client.post("/api/v1/profiles/Default", json={}).status_code == 401
    assert client.post("/fct_saml/parse_remote_metadata", json={}).status_code == 401


def test_default_enrollment_requires_invitation():
    with pytest.raises(RegistrationError):
        EmsService().register(RegisterRequest(devid="unauthorized"))


def test_invitation_cannot_be_reused():
    service = EmsService(require_invitation=True, valid_invitations={"once"})
    service.register(RegisterRequest(devid="first", invitation="once"))
    with pytest.raises(RegistrationError):
        service.register(RegisterRequest(devid="second", invitation="once"))


def test_reregistration_does_not_reveal_device_identity(secured):
    client, _, _ = secured
    enrolled = enroll(client)
    stolen = client.post("/fct/api/public/v1/register/", json={"devid": "pc"})
    assert stolen.status_code in {400, 401, 403}
    assert enrolled["client_id"] not in stolen.text
    assert "device_token" not in stolen.json()


def test_device_token_required_for_policy_and_telemetry(secured):
    client, _, admin = secured
    enrolled = enroll(client)
    client.post("/api/v1/profiles/Default", headers=admin, json={"web_filter": {"blocked": ["example.com"]}})
    params = {"client_id": enrolled["client_id"]}
    assert client.get("/fct/api/public/v1/config/assigned/", params=params).status_code == 401
    assert client.get("/fct/api/public/v1/config/", params={"vdom": "Default"}).status_code == 401
    assert client.post("/fct/api/public/v1/host_tags/", json={**params, "tags": []}).status_code == 401
    device = {"Authorization": f"Bearer {enrolled['device_token']}"}
    response = client.get("/fct/api/public/v1/config/assigned/", params=params, headers=device)
    assert response.status_code == 200
    assert len(response.json()["digest"]) == 64
    assert client.get("/api/v1/endpoints/index", headers=device).status_code == 401


def test_invites_are_group_bound_and_finite(secured):
    client, _, admin = secured
    response = client.post("/api/v1/enrollment/invitations", headers=admin, json={"vdom": "Strict", "max_uses": 1, "ttl_seconds": 600})
    assert response.status_code == 200
    invitation = response.json()["invitation"]
    wrong = client.post("/fct/api/public/v1/register/", json={"devid": "wrong", "vdom": "Default", "invitation": invitation})
    assert wrong.status_code == 400
    right = client.post("/fct/api/public/v1/register/", json={"devid": "right", "vdom": "Strict", "invitation": invitation})
    assert right.status_code == 200
    reused = client.post("/fct/api/public/v1/register/", json={"devid": "reuse", "vdom": "Strict", "invitation": invitation})
    assert reused.status_code == 400
    assert invitation not in client.get("/api/v1/audit", headers=admin).text


def test_devices_cannot_access_another_identity(secured):
    client, _, admin = secured
    first = enroll(client)
    invitation = client.post("/api/v1/enrollment/invitations", headers=admin, json={}).json()["invitation"]
    second = client.post("/fct/api/public/v1/register/", json={"devid": "second", "invitation": invitation}).json()
    device = {"Authorization": f"Bearer {first['device_token']}"}
    for route in ("refresh", "messages/pull", "host_tags", "config/ack"):
        response = client.post(f"/fct/api/public/v1/{route}/", headers=device, json={"client_id": second["client_id"], "tags": [], "version": 1})
        assert response.status_code == 401


def test_ack_requires_actual_assignment_and_preserves_state_on_reregister(secured):
    client, service, admin = secured
    enrolled = enroll(client)
    device = {"Authorization": f"Bearer {enrolled['device_token']}"}
    identity = {"client_id": enrolled["client_id"]}
    for vdom in ("Default", "Strict"):
        client.post(f"/api/v1/profiles/{vdom}", headers=admin, json={"web_filter": {"blocked": [f"{vdom.lower()}.test"]}})
    assigned = client.get("/fct/api/public/v1/config/assigned/", params=identity, headers=device).json()
    ack = {**identity, "vdom": assigned["vdom"], "version": assigned["version"], "digest": assigned["digest"], "success": True}
    assert client.post("/fct/api/public/v1/config/ack/", headers=device, json=ack).status_code == 200
    for patch in ({"version": -1}, {"version": 42}, {"digest": "0" * 64}, {"vdom": "Strict"}):
        assert client.post("/fct/api/public/v1/config/ack/", headers=device, json={**ack, **patch}).status_code in {409, 422}
    reregistered = client.post("/fct/api/public/v1/register/", json={"devid": "pc", "key": enrolled["device_token"]})
    assert reregistered.status_code == 200
    assert reregistered.json().get("device_token") in {None, ""}
    detail = client.get("/api/v1/endpoints/detail", params={"devid": "pc"}, headers=admin).json()
    assert detail["config_version"] == 1 and detail["applied_vdom"] == "Default"
    assert detail["last_applied"]
    assert enrolled["device_token"] not in str(detail)
    service.add_rule(AssignmentRule(id="move", target_vdom="Strict"))
    detail = client.get("/api/v1/endpoints/detail", params={"devid": "pc"}, headers=admin).json()
    assert detail["desired_profile"]["vdom"] == "Strict" and detail["applied_vdom"] == "Default"
    assert client.post("/fct/api/public/v1/config/ack/", headers=device, json=ack).status_code == 409


def test_failed_apply_and_offline_are_visible(secured):
    client, service, admin = secured
    enrolled = enroll(client)
    client.post("/api/v1/profiles/Default", headers=admin, json={})
    identity = {"client_id": enrolled["client_id"]}
    device = {"Authorization": f"Bearer {enrolled['device_token']}"}
    assigned = client.get("/fct/api/public/v1/config/assigned/", params=identity, headers=device).json()
    ack = {**identity, "vdom": "Default", "version": 1, "digest": assigned["digest"], "success": False, "error": "Hosts permission denied"}
    assert client.post("/fct/api/public/v1/config/ack/", headers=device, json=ack).status_code == 200
    endpoint = service.get_endpoint("pc")
    endpoint.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
    service._store.upsert(endpoint)
    detail = client.get("/api/v1/endpoints/detail", params={"devid": "pc"}, headers=admin).json()
    assert detail["online"] is False
    assert detail["last_error"] == "Hosts permission denied"
    assert detail["config_version"] == 0


def test_revoked_and_rotated_device_tokens_stop_working(secured):
    client, _, admin = secured
    enrolled = enroll(client)
    device = {"Authorization": f"Bearer {enrolled['device_token']}"}
    identity = {"client_id": enrolled["client_id"]}
    rotated = client.post("/api/v1/endpoints/credentials/rotate", headers=admin, json={"devid": "pc"})
    assert rotated.status_code == 200
    assert rotated.json()["device_token"] != enrolled["device_token"]
    assert client.post("/fct/api/public/v1/refresh/", headers=device, json=identity).status_code == 401
    new_device = {"Authorization": f"Bearer {rotated.json()['device_token']}"}
    assert client.post("/fct/api/public/v1/refresh/", headers=new_device, json=identity).status_code == 200
    assert client.post("/api/v1/endpoints/revoke", headers=admin, json={"devid": "pc"}).status_code == 200
    assert client.post("/fct/api/public/v1/refresh/", headers=new_device, json=identity).status_code == 401


def test_cookie_login_has_csrf_and_logout_revokes_session(secured):
    client, _, _ = secured
    logged = client.post("/api/v1/auth/login", json={"username": "operator", "password": "test-password"})
    assert "HttpOnly" in logged.headers["set-cookie"]
    assert "SameSite=strict" in logged.headers["set-cookie"]
    # Secure cookies are not sent by HTTP test clients; transfer via HTTPS.
    client.base_url = "https://testserver"
    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200
    assert client.post("/api/v1/profiles/Default", json={}).status_code == 403
    csrf = {"X-CSRF-Token": session.json()["csrf_token"]}
    assert client.post("/api/v1/profiles/Default", headers=csrf, json={}).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=csrf).status_code == 200
    assert client.get("/api/v1/auth/session").status_code == 401


def test_invalid_payload_and_oversize_requests_rejected(secured):
    client, _, admin = secured
    for body in ({"web_filter": {"blocked": "example.com"}}, {"web_filter": {"blocked": ["*.example.com"]}}, {"app_control": {"blocked": ["../app.exe"]}}):
        assert client.post("/api/v1/profiles/Default", headers=admin, json=body).status_code == 422
    assert client.post("/api/v1/assignment_rules", headers=admin, json={"id": "r", "target_vdom": "x", "conditions": [{"field": "unknown", "op": "equals", "value": "a"}]}).status_code == 422
    assert client.post("/fct/api/public/v1/register/", json={"devid": "x" * 2_000_000}).status_code == 413
