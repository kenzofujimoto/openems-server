"""Block log on the server: device uploads, validation, aggregation and retention."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.events import BlockEvent, InMemoryEventStore
from app.service import EmsService


def this_hour() -> datetime:
    return datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


def stamp(when: datetime) -> str:
    return when.isoformat().replace("+00:00", "Z")


def enrolled(store: InMemoryEventStore, **options):
    client = TestClient(create_app(EmsService(require_invitation=False), event_store=store, **options))
    device = client.post("/fct/api/public/v1/register/", json={"devid": "RSM-SP-001"}).json()
    return client, device, {"Authorization": f"Bearer {device['device_token']}"}


def upload(client, device, auth, events, dropped=0):
    return client.post("/fct/api/public/v1/events/", headers=auth,
                       json={"client_id": device["client_id"], "events": events, "dropped": dropped})


def row(domain="steamcommunity.com", reason="category", category="games", count=1, hour=None):
    event = {"hour": stamp(hour or this_hour()), "domain": domain, "reason": reason, "count": count}
    if category is not None:
        event["category"] = category
    return event


def test_uploads_are_summed_per_machine_hour_domain_and_reason():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    first = upload(client, device, auth, [row(count=2), row(domain="www.example.com", reason="rule", category=None)])
    assert first.status_code == 200 and first.json() == {"accepted": 2, "rejected": 0}
    assert upload(client, device, auth, [row(count=3)]).status_code == 200
    events = {(event.domain, event.reason): event for event in store.recent(10)}
    assert events[("steamcommunity.com", "category")].count == 5
    assert events[("steamcommunity.com", "category")].devid == "RSM-SP-001"
    assert events[("steamcommunity.com", "category")].category == "games"
    assert events[("www.example.com", "rule")].category == ""


def test_uploads_require_the_device_credential():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    other = client.post("/fct/api/public/v1/register/", json={"devid": "RSM-SP-002"}).json()
    assert upload(client, device, {}, [row()]).status_code == 401
    # A device cannot write rows for another machine.
    assert upload(client, other, auth, [row()]).status_code == 401
    assert store.recent(10) == []


def test_invalid_rows_are_skipped_and_counted():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    now = this_hour()
    response = upload(client, device, auth, [
        row(),
        row(domain="exa mple.com"),
        row(category="altavista"),
        row(reason="rule", category="games"),
        row(reason="category", category=None),
        row(hour=now + timedelta(minutes=30)),
        row(hour=now + timedelta(hours=2)),
        row(hour=now - timedelta(days=31)),
        row(domain="Store.SteamPowered.com."),
    ])
    assert response.json() == {"accepted": 2, "rejected": 7}
    assert sorted(event.domain for event in store.recent(10)) == ["steamcommunity.com", "store.steampowered.com"]


@pytest.mark.parametrize("payload", [
    {"events": [row(count=0)]},
    {"events": [row(count=100_001)]},
    {"events": [row(reason="dropped")]},
    {"events": [row()] * 5001},
    {"events": [], "dropped": -1},
    {"events": [{**row(), "user": "kenzo"}]},
])
def test_malformed_uploads_are_refused(payload):
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    response = client.post("/fct/api/public/v1/events/", headers=auth, json={"client_id": device["client_id"], **payload})
    assert response.status_code in (413, 422)
    assert store.recent(10) == []


def test_dropped_events_are_kept_as_their_own_row():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    assert upload(client, device, auth, [], dropped=40).json() == {"accepted": 0, "rejected": 0}
    [dropped] = store.recent(10)
    assert (dropped.reason, dropped.domain, dropped.count, dropped.hour) == ("dropped", "", 40, this_hour())


def test_rows_past_retention_are_purged_on_upload():
    store = InMemoryEventStore()
    old = this_hour() - timedelta(days=8)
    store.add([BlockEvent(devid="RSM-SP-009", hour=old, domain="old.example", reason="rule", category="", count=1)])
    client, device, auth = enrolled(store, event_retention_days=7)
    assert upload(client, device, auth, [row(hour=old)]).json() == {"accepted": 0, "rejected": 1}
    assert [event.domain for event in store.recent(10)] == []
    assert upload(client, device, auth, [row()]).json()["accepted"] == 1


@pytest.mark.parametrize("days", [0, 366])
def test_retention_must_stay_within_a_year(days):
    with pytest.raises(ValueError):
        create_app(EmsService(require_invitation=False), event_store=InMemoryEventStore(), event_retention_days=days)


def test_postgres_store_sums_and_purges():
    dsn = os.environ.get("OPENEMS_TEST_DSN")
    if not dsn:
        pytest.skip("OPENEMS_TEST_DSN not set")
    from app.events import PostgresEventStore

    store = PostgresEventStore(dsn)
    store.init_schema()
    with store._conn.cursor() as cur:
        cur.execute("TRUNCATE block_events")
    hour = this_hour()
    event = BlockEvent(devid="pc", hour=hour, domain="steamcommunity.com", reason="category", category="games", count=2)
    store.add([event, event])
    store.add([BlockEvent(devid="pc", hour=hour - timedelta(days=40), domain="old.example", reason="rule", category="", count=1)])
    assert [(item.domain, item.count) for item in store.recent(10)] == [("steamcommunity.com", 4), ("old.example", 1)]
    assert store.top_domains(hour - timedelta(days=50), 5) == [("steamcommunity.com", 4), ("old.example", 1)]
    assert store.daily_totals(hour - timedelta(days=1)) == {hour.date(): 4}
    assert store.purge(hour - timedelta(days=30)) == 1
    assert [item.domain for item in store.recent(10)] == ["steamcommunity.com"]
    store.close()
