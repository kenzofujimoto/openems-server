"""F6 server contracts: validated definitions, group mappings and actual-policy ACKs."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import RegisterRequest
from app.service import EmsService


def office(**overrides):
    return {"id": "sp", "name": "Escritório SP", "cidrs": ["192.168.1.22/24"],
            "gateway_macs": ["00-11-22-33-44-55"], "dns_suffixes": [], "public_cidrs": [],
            "probe": None, **overrides}


@pytest.fixture
def setup():
    service = EmsService(require_invitation=False)
    audit = InMemoryAuditLog()
    client = TestClient(create_app(service, lab_mode=True, audit_log=audit))
    service.set_profile("Default", {"web_filter": {"blocked": ["example.com"]}})
    service.set_profile("Office", {"web_filter": {"blocked": []}})
    endpoint = service.register(RegisterRequest(devid="pc"))
    return service, audit, client, endpoint


def test_location_crud_normalizes_signals_and_audits_changes(setup):
    _, audit, client, _ = setup
    result = client.post("/api/v1/network_locations", json=office())
    assert result.status_code == 200
    listed = client.get("/api/v1/network_locations").json()
    assert listed[0]["cidrs"] == ["192.168.1.0/24"]
    assert listed[0]["gateway_macs"] == ["001122334455"]
    assert client.post("/api/v1/network_locations", json=office()).status_code == 409
    assert client.put("/api/v1/network_locations/sp", json=office(name="São Paulo")).status_code == 200
    assert client.get("/api/v1/network_locations").json()[0]["name"] == "São Paulo"
    assert client.put("/api/v1/network_locations/absent", json=office(id="absent")).status_code == 404
    assert client.put("/api/v1/network_locations/sp", json=office(id="different")).status_code == 422
    assert client.delete("/api/v1/network_locations/sp").status_code == 200
    assert client.delete("/api/v1/network_locations/sp").status_code == 404
    assert client.get("/api/v1/network_locations").json() == []
    assert {entry.action for entry in audit.list()} >= {"network_location.create", "network_location.update", "network_location.delete"}


@pytest.mark.parametrize("changes", [
    {"gateway_macs": []}, {"cidrs": ["bad"]}, {"gateway_macs": ["bad"]},
    {"dns_suffixes": [""]}, {"dns_suffixes": ["invalid/suffix"]},
    {"public_cidrs": ["10.0.0.1/33"]}, {"id": "has space"},
    {"probe": {"host": "https://intranet.example/path", "port": 443, "sha256": "a" * 64}},
    {"probe": {"host": "intranet.example", "port": 0, "sha256": "a" * 64}},
    {"probe": {"host": "intranet.example", "port": 443, "sha256": "no"}},
])
def test_invalid_or_insufficient_signals_are_rejected(setup, changes):
    assert setup[2].post("/api/v1/network_locations", json=office(**changes)).status_code == 422


def test_public_range_or_two_distinct_local_types_are_sufficient(setup):
    client = setup[2]
    assert client.post("/api/v1/network_locations", json=office(cidrs=[], gateway_macs=[], public_cidrs=["200.1.2.3/24"])).status_code == 200
    assert client.put("/api/v1/network_locations/sp", json=office(cidrs=[], dns_suffixes=["Corp.Example."])).status_code == 200
    assert client.get("/api/v1/network_locations").json()[0]["dns_suffixes"] == ["corp.example"]


def test_assignment_contains_only_the_effective_group_mappings_in_name_order(setup):
    service, _, client, endpoint = setup
    for identifier, name in [("z", "Zulu"), ("a", "Alpha")]:
        assert client.post("/api/v1/network_locations", json=office(id=identifier, name=name)).status_code == 200
        assert client.post("/api/v1/location_policies", json={"vdom": "Default", "location_id": identifier, "inside_vdom": "Office"}).status_code == 200
    raw = client.get("/fct/api/public/v1/config/assigned/", params={"client_id": endpoint.client_id}).json()
    assert [entry["id"] for entry in raw["locations"]] == ["a", "z"]
    assert raw["locations"][0]["assignment"]["digest"] == service.get_profile("Office").digest
    assert raw["vdom"] == "Default" and raw["client_ip"] == "testclient"
    service.set_profile("Office", {"web_filter": {"blocked": ["inside.example"]}})
    raw = client.get("/fct/api/public/v1/config/assigned/", params={"client_id": endpoint.client_id}).json()
    assert raw["locations"][0]["assignment"]["version"] == 2
    assert raw["locations"][0]["assignment"]["body"]["web_filter"]["blocked"] == ["inside.example"]


def test_mappings_validate_references_upsert_delete_and_cascade(setup):
    _, audit, client, _ = setup
    mapping = {"vdom": "Default", "location_id": "sp", "inside_vdom": "Office"}
    assert client.post("/api/v1/location_policies", json=mapping).status_code == 404
    client.post("/api/v1/network_locations", json=office())
    assert client.post("/api/v1/location_policies", json={**mapping, "inside_vdom": "missing"}).status_code == 404
    assert client.post("/api/v1/location_policies", json=mapping).status_code == 200
    assert client.post("/api/v1/location_policies", json={**mapping, "inside_vdom": "Default"}).status_code == 200
    assert client.get("/api/v1/location_policies").json() == [{**mapping, "inside_vdom": "Default"}]
    params = {"vdom": "Default", "location_id": "sp"}
    assert client.delete("/api/v1/location_policies", params=params).status_code == 200
    assert client.delete("/api/v1/location_policies", params=params).status_code == 404
    client.post("/api/v1/location_policies", json=mapping)
    client.delete("/api/v1/network_locations/sp")
    assert client.get("/api/v1/location_policies").json() == []
    assert {entry.action for entry in audit.list()} >= {"location_policy.set", "location_policy.delete"}


def test_inside_ack_reports_the_actual_policy_and_leaving_restores_outside(setup):
    service, _, client, endpoint = setup
    client.post("/api/v1/network_locations", json=office())
    client.post("/api/v1/location_policies", json={"vdom": "Default", "location_id": "sp", "inside_vdom": "Office"})
    inside = service.get_profile("Office")
    ack = {"client_id": endpoint.client_id, "vdom": "Office", "version": inside.version, "digest": inside.digest, "location": "sp"}
    assert client.post("/fct/api/public/v1/config/ack/", json=ack).status_code == 200
    detail = client.get("/api/v1/endpoints/detail", params={"devid": "pc"}).json()
    assert detail["location"] == "sp" and detail["location_name"] == "Escritório SP"
    assert detail["applied_vdom"] == "Office" and detail["desired_profile"]["vdom"] == "Office"
    assert client.post("/fct/api/public/v1/config/ack/", json={**ack, "location": "unknown"}).status_code == 409
    assert client.post("/fct/api/public/v1/config/ack/", json={**ack, "digest": "a" * 64}).status_code == 409
    assert client.post("/fct/api/public/v1/config/ack/", json={**ack, "location": ""}).status_code == 409
    assert client.post("/fct/api/public/v1/config/ack/", json={**ack, "location": "sp", "vdom": "Default"}).status_code == 409
    outside = service.get_profile("Default")
    assert client.post("/fct/api/public/v1/config/ack/", json={**ack, "location": "", "vdom": "Default", "digest": outside.digest}).status_code == 200
    assert service.get_endpoint("pc").location == ""


def test_failed_inside_ack_does_not_replace_last_applied_location(setup):
    service, _, client, endpoint = setup
    client.post("/api/v1/network_locations", json=office())
    client.post("/api/v1/location_policies", json={"vdom": "Default", "location_id": "sp", "inside_vdom": "Office"})
    profile = service.get_profile("Office")
    response = client.post("/fct/api/public/v1/config/ack/", json={"client_id": endpoint.client_id, "vdom": "Office", "version": 1, "digest": profile.digest, "location": "sp", "success": False, "error": "denied"})
    assert response.status_code == 200
    assert service.get_endpoint("pc").location == "" and service.get_endpoint("pc").last_error == "denied"


def test_public_ip_comes_from_transport_not_a_spoofed_forwarded_header():
    service = EmsService(require_invitation=False)
    endpoint = service.register(RegisterRequest(devid="pc"))
    app = create_app(service)
    with TestClient(app, client=("200.1.2.3", 50000)) as client:
        response = client.get("/fct/api/public/v1/config/assigned/", params={"client_id": endpoint.client_id}, headers={"Authorization": f"Bearer {endpoint.device_token}", "X-Forwarded-For": "1.2.3.4"})
    assert response.status_code == 200 and response.json()["client_ip"] == "200.1.2.3"
    assert response.json()["locations"] == []


def test_location_writes_require_admin_and_csrf():
    admin = AdminService(secret="tests")
    admin.add_admin("admin", "pw")
    admin.add_admin("reader", "pw", role="viewer")
    client = TestClient(create_app(EmsService(), admin_service=admin))
    assert client.post("/api/v1/network_locations", json=office()).status_code == 401
    reader = admin.issue_token("reader", "viewer")
    assert client.get("/api/v1/network_locations", headers={"Authorization": f"Bearer {reader}"}).status_code == 200
    assert client.post("/api/v1/network_locations", json=office(), headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    token = client.post("/api/v1/auth/login", json={"username": "admin", "password": "pw"}).json()["token"]
    assert token
    assert client.post("/api/v1/network_locations", json=office()).status_code == 403


def test_tls_proxy_trust_is_enabled_only_with_internal_server_port():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.tls.yml").read_text()
    assert 'FORWARDED_ALLOW_IPS: "*"' in compose
    assert "ports: !reset []" in compose


@pytest.fixture(params=["memory", "postgres"])
def location_store(request):
    from app.network_locations import InMemoryLocationStore, PostgresLocationStore

    if request.param == "memory":
        yield InMemoryLocationStore()
        return
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    import psycopg
    from psycopg.conninfo import make_conninfo
    schema = "test_locations_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(psycopg.sql.SQL("CREATE SCHEMA {}").format(psycopg.sql.Identifier(schema)))
    store = PostgresLocationStore(make_conninfo(dsn, options=f"-c search_path={schema}"))
    store.init_schema()
    try:
        yield store
    finally:
        store.close()
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(psycopg.sql.Identifier(schema)))


def test_location_store_roundtrip_and_cascade(location_store):
    from app.schemas import NetworkLocationPayload

    location = NetworkLocationPayload(**office()).model_dump()
    assert location_store.create(location)
    assert not location_store.create(location)
    location_store.set_mapping("Default", "sp", "Office")
    assert location_store.mappings() == [{"vdom": "Default", "location_id": "sp", "inside_vdom": "Office"}]
    location["name"] = "Updated"
    assert location_store.update(location)
    assert location_store.locations()[0]["name"] == "Updated"
    assert location_store.remove("sp")
    assert location_store.locations() == [] and location_store.mappings() == []


def test_endpoint_location_roundtrip_survives_other_updates():
    from app.models import Endpoint
    from app.stores import InMemoryStore

    store = InMemoryStore()
    endpoint = Endpoint(devid="pc", client_id="cid", location="sp")
    store.upsert(endpoint)
    endpoint = store.get_by_devid("pc")
    endpoint.hostname = "new"
    store.upsert(endpoint)
    assert store.get_by_devid("pc").location == "sp"
