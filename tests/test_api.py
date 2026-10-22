"""HTTP integration tests for the FastAPI layer (SPEC-INTEROP.md §2-3).

Uses Starlette's TestClient (requires fastapi + httpx, see requirements.txt).
Each test gets a fresh app wired to a fresh in-memory service.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from app.api import create_app
from app.saml import SamlSp
from app.service import EmsService


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(EmsService(require_invitation=False), lab_mode=True, saml_sp=SamlSp("http://localhost:8013", require_signature=False, require_audience=False)))


def test_register_returns_client_id(client: TestClient) -> None:
    resp = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["client_id"]
    assert body["status"] == "registered"


def test_register_without_devid_is_422(client: TestClient) -> None:
    resp = client.post("/fct/api/public/v1/register/", json={"hostname": "pc"})
    assert resp.status_code == 422


def test_refresh_unknown_client_is_404(client: TestClient) -> None:
    resp = client.post("/fct/api/public/v1/refresh/", json={"client_id": "nope"})
    assert resp.status_code == 404


def test_update_client_id_rotates(client: TestClient) -> None:
    cid = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"}).json()[
        "client_id"
    ]
    rotated = client.post(
        "/fct/api/public/v1/update_client_id/", json={"client_id": cid}
    ).json()["client_id"]
    assert rotated != cid


def test_endpoints_index_and_count(client: TestClient) -> None:
    client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"})
    client.post("/fct/api/public/v1/register/", json={"devid": "DEV-2"})
    assert client.get("/api/v1/endpoints/count").json() == {"count": 2}
    devids = {e["devid"] for e in client.get("/api/v1/endpoints/index").json()}
    assert devids == {"DEV-1", "DEV-2"}


def test_host_tags_report_roundtrip(client: TestClient) -> None:
    # register, then (via the service behind the app) the report route reads tags
    svc = EmsService(require_invitation=False)
    app_client = TestClient(create_app(svc, lab_mode=True))
    cid = app_client.post(
        "/fct/api/public/v1/register/", json={"devid": "DEV-9"}
    ).json()["client_id"]
    svc.ingest_host_tags(cid, ["compliant", "vpn-up"])
    resp = app_client.get("/api/v1/report/fct/host_tags", params={"devid": "DEV-9"})
    assert resp.status_code == 200
    assert resp.json()["host_tags"] == ["compliant", "vpn-up"]


def test_config_push_full_flow(client: TestClient) -> None:
    # 1. endpoint registers (no profile yet -> version 0)
    reg = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"}).json()
    assert reg["config_version"] == 0
    cid = reg["client_id"]

    # 2. admin publishes a profile for the vdom
    setp = client.post("/api/v1/profiles/Default", json={"firewall": "strict"})
    assert setp.status_code == 200 and setp.json()["version"] == 1

    # 3. endpoint pulls its queue and sees the update
    msgs = client.post(
        "/fct/api/public/v1/messages/pull/", json={"client_id": cid}
    ).json()["messages"]
    assert msgs == [{"type": "config_update", "vdom": "Default", "version": 1}]

    # 4. endpoint fetches the new config
    cfg = client.get("/fct/api/public/v1/config/", params={"vdom": "Default"}).json()
    assert cfg["version"] == 1 and cfg["body"] == {"firewall": "strict"}

    # 5. endpoint acks the applied version
    ack = client.post(
        "/fct/api/public/v1/config/ack/", json={"client_id": cid, "version": 1}
    ).json()
    assert ack["config_version"] == 1


def test_get_config_unknown_vdom_is_404(client: TestClient) -> None:
    assert client.get(
        "/fct/api/public/v1/config/", params={"vdom": "nope"}
    ).status_code == 404


# --- SAML SP ---------------------------------------------------------------

import base64

_IDP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://idp.example"><md:IDPSSODescriptor '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:SingleSignOnService '
    'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'
)

_SAML_RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    '<samlp:Status><samlp:StatusCode '
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion><saml:Subject><saml:NameID>bob@example.com</saml:NameID>'
    "</saml:Subject></saml:Assertion></samlp:Response>"
)


def test_saml_metadata_served_as_xml(client: TestClient) -> None:
    resp = client.get("/fct_saml/acme/metadata")
    assert resp.status_code == 200
    assert "application/xml" in resp.headers["content-type"]
    assert "SPSSODescriptor" in resp.text


def test_saml_login_redirects_after_idp_registered(client: TestClient) -> None:
    client.post(
        "/fct_saml/parse_remote_metadata",
        json={"prefix": "acme", "metadata": _IDP_METADATA},
    )
    resp = client.get(
        "/fct_saml/login", params={"prefix": "acme"}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://idp.example/sso?")


def test_saml_acs_consumes_response(client: TestClient) -> None:
    client.post(
        "/fct_saml/parse_remote_metadata",
        json={"prefix": "acme", "metadata": _IDP_METADATA},
    )
    b64 = base64.b64encode(_SAML_RESPONSE.encode()).decode()
    resp = client.post("/fct_saml/acme/acs", data={"SAMLResponse": b64})
    assert resp.status_code == 200
    assert resp.json()["name_id"] == "bob@example.com"


# --- group assignment rules ------------------------------------------------

def test_assignment_rule_add_list_and_assigned_config(client: TestClient) -> None:
    # 1. admin adds a rule: Windows endpoints -> "Strict" vdom
    rule = {
        "id": "win",
        "target_vdom": "Strict",
        "priority": 10,
        "conditions": [{"field": "os", "op": "contains", "value": "Windows"}],
    }
    assert client.post("/api/v1/assignment_rules", json=rule).status_code == 200
    listed = client.get("/api/v1/assignment_rules").json()
    assert listed[0]["id"] == "win" and listed[0]["target_vdom"] == "Strict"

    # 2. a Windows endpoint registers under Default but is assigned to Strict
    reg = client.post(
        "/fct/api/public/v1/register/", json={"devid": "DEV-1", "os": "Windows 11"}
    ).json()
    assert reg["vdom"] == "Strict"
    cid = reg["client_id"]

    # 3. admin publishes the Strict profile
    client.post("/api/v1/profiles/Strict", json={"firewall": "on"})

    # 4. endpoint fetches its *assigned* config by client_id
    cfg = client.get(
        "/fct/api/public/v1/config/assigned/", params={"client_id": cid}
    ).json()
    assert cfg["vdom"] == "Strict" and cfg["body"] == {"firewall": "on"}


# --- management web console -------------------------------------------------

def test_report_host_tags(client: TestClient) -> None:
    cid = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"}).json()[
        "client_id"
    ]
    r = client.post(
        "/fct/api/public/v1/host_tags/",
        json={"client_id": cid, "tags": ["os:win32", "vdom:Default"]},
    )
    assert r.status_code == 200
    tags = client.get(
        "/api/v1/report/fct/host_tags", params={"devid": "DEV-1"}
    ).json()["host_tags"]
    assert tags == ["os:win32", "vdom:Default"]


def test_report_host_tags_unknown_client(client: TestClient) -> None:
    assert client.post(
        "/fct/api/public/v1/host_tags/", json={"client_id": "nope", "tags": []}
    ).status_code == 404


def test_build_factory_without_backends() -> None:
    # the uvicorn factory must produce a working in-memory app when no
    # OPENEMS_DATABASE_URL / OPENEMS_REDIS_URL are set
    from app.api import build

    c = TestClient(build())
    assert c.get("/api/v1/endpoints/count").status_code == 401


def test_console_html_served(client: TestClient) -> None:
    resp = client.get("/console/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert "openems" in body and "Endpoints" in body


# --- console: detail / delete rule / list profiles -------------------------

def test_endpoint_detail(client: TestClient) -> None:
    client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1", "os": "Windows 11"})
    client.post("/api/v1/assignment_rules", json={
        "id": "win", "target_vdom": "Strict", "priority": 10,
        "conditions": [{"field": "os", "op": "contains", "value": "Windows"}]})
    d = client.get("/api/v1/endpoints/detail", params={"devid": "DEV-1"}).json()
    assert d["devid"] == "DEV-1"
    assert d["effective_vdom"] == "Strict"  # moved by the rule
    assert "config_version" in d and "last_seen" in d


def test_endpoint_detail_unknown_is_404(client: TestClient) -> None:
    assert client.get(
        "/api/v1/endpoints/detail", params={"devid": "ghost"}
    ).status_code == 404


def test_delete_rule(client: TestClient) -> None:
    client.post("/api/v1/assignment_rules", json={"id": "r1", "target_vdom": "A"})
    assert client.delete("/api/v1/assignment_rules/r1").status_code == 200
    assert client.get("/api/v1/assignment_rules").json() == []
    assert client.delete("/api/v1/assignment_rules/nope").status_code == 404


def test_list_profiles(client: TestClient) -> None:
    client.post("/api/v1/profiles/Default", json={"a": 1})
    client.post("/api/v1/profiles/Strict", json={"b": 2})
    vdoms = {p["vdom"] for p in client.get("/api/v1/profiles").json()}
    assert vdoms == {"Default", "Strict"}
