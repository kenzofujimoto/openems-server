"""HTTP integration tests for the FastAPI layer (SPEC-INTEROP.md §2-3).

Uses Starlette's TestClient (requires fastapi + httpx, see requirements.txt).
Each test gets a fresh app wired to a fresh in-memory service.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from app.api import create_app  # noqa: E402
from app.service import EmsService  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(EmsService()))


def test_register_returns_client_id(client: TestClient) -> None:
    resp = client.post("/fct/api/public/v1/register/", json={"devid": "DEV-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["client_id"]
    assert body["status"] == "registered"


def test_register_without_devid_is_400(client: TestClient) -> None:
    resp = client.post("/fct/api/public/v1/register/", json={"hostname": "pc"})
    assert resp.status_code == 400


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
    svc = EmsService()
    app_client = TestClient(create_app(svc))
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
