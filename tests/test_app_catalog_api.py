"""Catalog routes and catalog-driven profile expansion from real uploaded inventories."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.app_catalog import build_catalog
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.models import RegisterRequest
from app.service import EmsService
from tests.test_app_catalog import NOW, winget_index

EPIC = {"name": "Epic Games Launcher", "path": r"C:\Epic\EpicGamesLauncher.exe", "sha256": "b" * 64,
        "publisher": "CN=Epic Games Inc., O=Epic Games Inc., C=US", "version": "1", "running": True}
TORRENT = {"name": "qBittorrent", "path": r"C:\qBittorrent\qbittorrent.exe", "sha256": "c" * 64,
           "publisher": "", "version": "4", "running": False}
STEAM = {"name": "Steam", "path": r"C:\Steam\steam.exe", "sha256": "a" * 64,
         "publisher": "CN=Valve Corp., O=Valve Corp., C=US", "version": "2", "running": False}
MANUAL = {"id": "manual-tool", "kind": "hash", "value": "d" * 64}


@pytest.fixture
def harness(tmp_path):
    build_catalog(winget_index(tmp_path / "index.db"), tmp_path / "catalog", now=NOW)
    service = EmsService(valid_invitations={"one", "two"})
    first = service.register(RegisterRequest(devid="pc-1", invitation="one"))
    second = service.register(RegisterRequest(devid="pc-2", invitation="two"))
    admin = AdminService()
    admin.add_admin("operator", "test-password")
    audit = InMemoryAuditLog()
    client = TestClient(create_app(service, admin_service=admin, audit_log=audit, app_catalog_dir=tmp_path / "catalog"))
    management = {"Authorization": "Bearer " + admin.issue_token("operator", "admin")}
    return service, client, management, audit, first, second


def upload(client, endpoint, applications):
    payload = {"client_id": endpoint.client_id, "collected_at": datetime.now(UTC).isoformat(),
               "applications": applications, "usb_devices": []}
    response = client.post("/fct/api/public/v1/inventory/", json=payload, headers={"Authorization": "Bearer " + endpoint.device_token})
    assert response.status_code == 200, response.text


def test_catalog_summary_and_search_report_machines_where_apps_were_seen(harness):
    _, client, management, _, first, second = harness
    upload(client, first, [STEAM, EPIC])
    upload(client, second, [STEAM, TORRENT])
    summary = client.get("/api/v1/app_catalog", headers=management).json()
    assert summary["available"] is True and "MIT" in summary["attribution"]
    games = next(category for category in summary["categories"] if category["id"] == "games")
    assert games["label"] == "Jogos" and games["apps"] == 2 and games["observed_endpoints"] == 2
    assert summary["observed"] == {"EpicGames.EpicGamesLauncher": 1, "Valve.Steam": 2, "qBittorrent.qBittorrent": 1}
    found = client.get("/api/v1/app_catalog/search", params={"q": "steam"}, headers=management).json()
    assert [(app["id"], app["observed_endpoints"]) for app in found] == [("Valve.Steam", 2)]
    assert client.get("/api/v1/app_catalog", headers={}).status_code == 401


def test_publishing_catalog_actions_expands_present_only_rules_and_keeps_manual_rules(harness):
    service, client, management, _, first, second = harness
    upload(client, first, [STEAM, EPIC])
    upload(client, second, [TORRENT])
    body = {"app_control": {"execution_rules": [MANUAL, {"id": "catalog-stale", "kind": "hash", "value": "e" * 64, "if_present": True}]},
            "app_catalog": {"actions": {"category:games": "block", "app:Valve.Steam": "allow", "category:p2p": "block"}}}
    response = client.post("/api/v1/profiles/BPO", json=body, headers=management)
    assert response.status_code == 200, response.text
    stored = service.get_profile("BPO").body
    rules = stored["app_control"]["execution_rules"]
    assert rules[0] == MANUAL
    assert {(rule["kind"], rule["value"]) for rule in rules[1:]} == {("publisher", EPIC["publisher"]), ("hash", "c" * 64)}
    assert all(rule["if_present"] is True for rule in rules[1:])
    assert stored["app_catalog"] == body["app_catalog"]


def test_new_inventory_republishes_groups_whose_catalog_now_covers_more_identities(harness):
    service, client, management, audit, first, second = harness
    upload(client, first, [EPIC])
    body = {"app_catalog": {"actions": {"category:p2p": "block"}}}
    assert client.post("/api/v1/profiles/TI", json=body, headers=management).status_code == 200
    assert service.get_profile("TI").body["app_control"]["execution_rules"] == []
    upload(client, second, [TORRENT])
    profile = service.get_profile("TI")
    assert profile.version == 2
    assert [rule["value"] for rule in profile.body["app_control"]["execution_rules"]] == ["c" * 64]
    assert any(entry.action == "profile.catalog_refresh" and entry.target == "TI" for entry in audit.list())
    upload(client, second, [TORRENT])
    assert service.get_profile("TI").version == 2, "unchanged identities must not create new versions"


def test_invalid_catalog_actions_or_an_unavailable_catalog_are_refused(harness, tmp_path):
    _, client, management, _, _, _ = harness
    assert client.post("/api/v1/profiles/BPO", json={"app_catalog": {"actions": {"category:games": "maybe"}}}, headers=management).status_code == 422
    service = EmsService(valid_invitations=set())
    admin = AdminService()
    admin.add_admin("operator", "test-password")
    bare = TestClient(create_app(service, admin_service=admin))
    headers = {"Authorization": "Bearer " + admin.issue_token("operator", "admin")}
    assert bare.get("/api/v1/app_catalog", headers=headers).json()["available"] is False
    assert bare.post("/api/v1/profiles/BPO", json={"app_catalog": {"actions": {"category:games": "block"}}}, headers=headers).status_code == 422


def test_catalog_process_and_network_decisions_replace_only_their_generated_entries(harness):
    service, client, management, _, first, _ = harness
    upload(client, first, [EPIC, TORRENT])
    body = {"app_control": {"blocked": ["manual.exe"], "network_blocked": [r"C:\Manual\tool.exe"]},
            "app_catalog": {"actions": {"category:games": "block", "category:p2p": "block_network"}}}
    assert client.post("/api/v1/profiles/BPO", json=body, headers=management).status_code == 200
    controls = service.get_profile("BPO").body["app_control"]
    assert controls["blocked"] == ["manual.exe", "epicgameslauncher.exe"]
    assert controls["network_blocked"] == [r"C:\Manual\tool.exe", TORRENT["path"]]
    stored = service.get_profile("BPO").body
    body = {**stored, "app_catalog": {**stored["app_catalog"], "actions": {"category:p2p": "block_network"}}}
    assert client.post("/api/v1/profiles/BPO", json=body, headers=management).status_code == 200
    controls = service.get_profile("BPO").body["app_control"]
    assert controls["blocked"] == ["manual.exe"]
    assert controls["network_blocked"] == [r"C:\Manual\tool.exe", TORRENT["path"]]
