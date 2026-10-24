"""Panel side of the block log: events, overview, categories, capability warnings and view auditing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.audit import InMemoryAuditLog
from app.auth import AdminService
from app.capabilities import required_tags
from app.categories import build_categories
from app.events import BlockEvent, InMemoryEventStore, current_hour
from app.service import EmsService


def panel(store=None, audit=None, category_dir=None, role="admin"):
    admins = AdminService(secret="block-log-panel-test-secret-0123456789")
    admins.add_admin("operator", "pw", role=role)
    client = TestClient(create_app(EmsService(require_invitation=False), admin_service=admins,
                                   event_store=store or InMemoryEventStore(), audit_log=audit,
                                   category_dir=category_dir))
    token = client.post("/api/v1/auth/login", json={"username": "operator", "password": "pw"}).json()["token"]
    return client, {"Authorization": f"Bearer {token}"}


def event(domain, count, hour, reason="category", category="games", devid="RSM-SP-001"):
    return BlockEvent(devid=devid, hour=hour, domain=domain, reason=reason, category=category, count=count)


def test_events_list_newest_rows_with_reason_category_and_count():
    store = InMemoryEventStore()
    now = current_hour()
    store.add([
        event("steamcommunity.com", 12, now),
        event("www.example.com", 3, now - timedelta(hours=2), reason="rule", category=""),
        event("", 40, now - timedelta(hours=1), reason="dropped", category=""),
    ])
    client, auth = panel(store)
    assert client.get("/api/v1/events").status_code == 401
    rows = client.get("/api/v1/events?limit=8", headers=auth).json()
    assert [(row["detail"], row["reason"], row["count"]) for row in rows] == [
        ("steamcommunity.com", "category", 12),
        ("eventos não registrados pelo limite do agente", "dropped", 40),
        ("www.example.com", "rule", 3),
    ]
    first = rows[0]
    assert first["kind"] == "web_block" and first["devid"] == "RSM-SP-001"
    assert first["category"] == "games" and first["category_label"] == "Jogos"
    assert datetime.fromisoformat(first["at"]) == now
    assert len({row["id"] for row in rows}) == 3
    assert rows[2]["category"] is None and rows[2]["category_label"] is None
    assert len(client.get("/api/v1/events?limit=1", headers=auth).json()) == 1
    assert client.get("/api/v1/events?limit=0", headers=auth).status_code == 422


def test_overview_sums_seven_days_and_compares_with_the_week_before():
    store = InMemoryEventStore()
    today = current_hour().replace(hour=0)
    store.add([
        event("tiktok.com", 10, today),
        event("tiktok.com", 5, today - timedelta(days=1), devid="RSM-SP-002"),
        event("facebook.com", 7, today - timedelta(days=6)),
        event("", 4, today, reason="dropped", category=""),
        event("old.example", 9, today - timedelta(days=8)),
    ])
    client, auth = panel(store)
    overview = client.get("/api/v1/stats/overview", headers=auth).json()
    days = overview["blocks_by_day"]
    assert len(days) == 7 and days[-1]["date"] == today.date().isoformat()
    assert days[-1] == {"date": today.date().isoformat(), "web": 14, "apps": 0, "usb": 0}
    assert days[-2]["web"] == 5 and days[0]["web"] == 7
    # Dropped rows count as blocks but have no domain to rank.
    assert overview["top_domains"] == [{"domain": "tiktok.com", "count": 15}, {"domain": "facebook.com", "count": 7}]
    # The server keeps no history of machine status: only blocks can be compared.
    assert overview["previous_period"] == {"blocks": 9}
    assert datetime.fromisoformat(overview["generated_at"]).tzinfo is not None
    # The panel states how long the block log is kept next to the events.
    assert overview["retention_days"] == 30


def test_viewers_can_read_the_block_log_and_each_view_is_audited_once_per_hour():
    audit = InMemoryAuditLog()
    client, auth = panel(audit=audit, role="viewer")
    for _ in range(3):
        assert client.get("/api/v1/events?limit=8", headers=auth).status_code == 200
        assert client.get("/api/v1/stats/overview", headers=auth).status_code == 200
    views = [(entry.actor, entry.action, entry.target) for entry in audit.list(50) if entry.action == "events.read"]
    assert sorted(views) == [("operator", "events.read", "/api/v1/events"),
                             ("operator", "events.read", "/api/v1/stats/overview")]


def test_categories_route_lists_published_categories_with_attribution(tmp_path):
    source = tmp_path / "blacklists"
    (source / "games").mkdir(parents=True)
    (source / "games" / "domains").write_text("steampowered.com\nsteamcommunity.com\n", encoding="utf-8")
    build_categories(source, tmp_path / "published", now=datetime(2026, 10, 24, tzinfo=UTC))
    client, auth = panel(category_dir=tmp_path / "published")
    published = client.get("/api/v1/categories", headers=auth).json()
    assert published["version"] == "2026-10-24T00:00:00Z"
    assert "CC BY-SA 4.0" in published["attribution"]
    assert published["categories"] == [{"id": "games", "label": "Jogos", "group": "Consumo de banda e lazer", "count": 2}]
    empty, empty_auth = panel()
    assert empty.get("/api/v1/categories", headers=empty_auth).json() == {"version": None, "attribution": "", "categories": []}


@pytest.mark.parametrize(("web_filter", "tags"), [
    ({"blocked": ["example.com"]}, []),
    ({"blocked": ["*.example.com"]}, ["web-filter:dns"]),
    ({"safe_search": {"engines": ["google"]}}, ["web-filter:v2", "web-filter:dns"]),
    ({"timezone": "UTC", "scheduled": [{"blocked": ["x.com"], "days": ["mon"], "from": "08:00", "to": "09:00"}]},
     ["web-filter:v2"]),
    ({"blocked_categories": ["games"]}, ["web-filter:categories", "web-filter:dns"]),
    ({"timezone": "UTC", "scheduled": [{"blocked_categories": ["social"], "days": ["mon"], "from": "08:00", "to": "09:00"}]},
     ["web-filter:v2", "web-filter:categories", "web-filter:dns"]),
])
def test_policies_name_the_agent_capabilities_they_need(web_filter, tags):
    assert required_tags({"web_filter": web_filter}) == tags


def test_endpoints_and_publishing_warn_about_agents_missing_capabilities():
    client, auth = panel()
    devices = {}
    for devid, tags in (("old-pc", ["web-filter:v2"]), ("new-pc", ["web-filter:v2", "web-filter:categories", "web-filter:dns"])):
        device = client.post("/fct/api/public/v1/register/", json={"devid": devid}).json()
        client.post("/fct/api/public/v1/host_tags/", headers={"Authorization": f"Bearer {device['device_token']}"},
                    json={"client_id": device["client_id"], "tags": tags})
        devices[devid] = device
    published = client.post("/api/v1/profiles/Default", headers=auth, json={"web_filter": {"blocked_categories": ["games"]}})
    assert published.status_code == 200
    assert published.json()["warnings"] == [{"devid": "old-pc", "missing": ["web-filter:categories", "web-filter:dns"]}]
    views = {view["devid"]: view for view in client.get("/api/v1/endpoints/index", headers=auth).json()}
    assert views["old-pc"]["missing_capabilities"] == ["web-filter:categories", "web-filter:dns"]
    assert views["new-pc"]["missing_capabilities"] == []
    plain = client.post("/api/v1/profiles/Default", headers=auth, json={"web_filter": {"blocked": ["example.com"]}})
    assert plain.json()["warnings"] == []
