"""Web observations stay separate from blocks and retry batches are idempotent."""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.capabilities import required_tags
from app.events import BlockEvent, InMemoryEventStore, current_hour
from tests.test_block_events import enrolled, row
from tests.test_block_log_panel import panel
from tests.test_migrations import database  # noqa: F401 - shared disposable schema fixture


def send(client, device, auth, rows, batch_id=None):
    payload = {"client_id": device["client_id"], "events": rows}
    if batch_id is not None:
        payload["batch_id"] = batch_id
    return client.post("/fct/api/public/v1/events/", headers=auth, json=payload)


def test_monitoring_uploads_are_visible_and_never_inflate_block_statistics():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    response = send(client, device, auth, [row(count=2), {
        **row(count=8), "action": "monitored", "source": "dns",
    }, {**row(domain="unclassified.example", reason="policy", category=None), "action": "monitored"}])
    assert response.status_code == 200
    assert response.json() == {"accepted": 3, "rejected": 0}
    reader, headers = panel(store)
    events = reader.get("/api/v1/events", headers=headers).json()
    assert {event["kind"] for event in events} == {"web_block", "web_monitor"}
    assert len({event["id"] for event in events}) == 3
    assert all(event["source"] == "dns" for event in events)
    assert len(reader.get("/api/v1/events?action=monitored", headers=headers).json()) == 2
    blocks = reader.get("/api/v1/events?action=blocked", headers=headers).json()
    assert [event["count"] for event in blocks] == [2]
    overview = reader.get("/api/v1/stats/overview", headers=headers).json()
    assert sum(day["web"] for day in overview["blocks_by_day"]) == 2
    assert sum(day["web"] for day in overview["monitoring_by_day"]) == 9
    assert overview["top_domains"] == [{"domain": "steamcommunity.com", "count": 2}]


@pytest.mark.parametrize("patch", [
    {"action": "allow"}, {"source": "browser"},
    {"action": "monitored", "reason": "doh", "category": None},
    {"action": "blocked", "reason": "policy", "category": None},
])
def test_unsupported_actions_and_impossible_reason_pairs_cannot_be_stored(patch):
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    response = send(client, device, auth, [{**row(), **patch}])
    assert response.status_code == 422 or response.json()["accepted"] == 0
    assert store.recent(10) == []


def test_stable_batch_retries_do_not_repeat_counts_and_payload_reuse_is_rejected():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    batch_id = "a" * 64
    for duplicate in (False, True):
        response = send(client, device, auth, [{**row(count=4), "action": "monitored"}], batch_id)
        assert response.status_code == 200
        assert response.json()["duplicate"] is duplicate
    assert store.recent(10)[0].count == 4
    assert send(client, device, auth, [row(count=5)], batch_id).status_code == 409
    assert store.recent(10)[0].count == 4
    other = client.post("/fct/api/public/v1/register/", json={"devid": "other"}).json()
    other_auth = {"Authorization": f"Bearer {other['device_token']}"}
    assert send(client, other, other_auth, [row(count=1)], batch_id).status_code == 200
    assert len(store.recent(10)) == 2


def test_batch_id_is_bounded_and_device_auth_remains_required():
    store = InMemoryEventStore()
    client, device, auth = enrolled(store)
    for batch in ("", "x" * 64, "a" * 65):
        assert send(client, device, auth, [row()], batch).status_code == 422
    assert send(client, device, {}, [row()], "a" * 64).status_code == 401
    assert store.recent(10) == []


def test_memory_store_keeps_actions_separate_and_purges_monitoring():
    store = InMemoryEventStore()
    now = current_hour()
    common = {"devid": "pc", "hour": now, "domain": "same.example", "reason": "category", "category": "games"}
    store.add([BlockEvent(**common, count=2), BlockEvent(**common, count=9, action="monitored")])
    assert len(store.recent(10)) == 2
    assert store.daily_totals(now) == {now.date(): 2}
    assert store.daily_totals(now, action="monitored") == {now.date(): 9}
    assert store.top_domains(now, 5) == [("same.example", 2)]
    assert store.purge(now + timedelta(hours=1)) == 2
    assert store.recent(10) == []


def test_dropped_rows_are_reported_separately_from_observed_blocks_or_monitoring():
    store = InMemoryEventStore()
    store.add([BlockEvent(devid="pc", hour=current_hour(), domain="", reason="dropped", category="", count=9)])
    reader, auth = panel(store)
    overview = reader.get("/api/v1/stats/overview", headers=auth).json()
    assert sum(day["web"] for day in overview["blocks_by_day"]) == 0
    assert sum(day["web"] for day in overview["monitoring_by_day"]) == 0
    assert sum(day["web"] for day in overview["dropped_by_day"]) == 9


def test_policy_capabilities_cover_scheduled_actions_and_global_monitoring():
    tags = required_tags({"web_filter": {"category_actions": {"games": "monitor"}}})
    assert {"web-filter:actions", "web-filter:monitor", "web-filter:categories", "web-filter:dns"} <= set(tags)
    assert set(required_tags({"web_filter": {"monitor_all": True}})) >= {
        "web-filter:actions", "web-filter:monitor", "web-filter:dns",
    }
    scheduled = required_tags({"web_filter": {"scheduled": [{"category_actions": {"games": "block"}}]}})
    assert "web-filter:actions" in scheduled and "web-filter:categories" in scheduled
    assert "web-filter:monitor" not in scheduled
    assert "web-filter:actions" in required_tags({"web_filter": {"category_actions": {"games": "allow"}}})


def test_allow_category_exclusions_require_category_data_during_global_monitoring():
    tags = required_tags({"web_filter": {
        "monitor_all": True, "category_actions": {"games": "allow"},
    }})
    assert "web-filter:categories" in tags


def test_tamper_write_cannot_join_another_threads_web_batch_transaction():
    import threading
    from contextlib import contextmanager

    from app.events import PostgresEventStore, TamperEvent

    accessed = threading.Event()
    started = threading.Event()

    class Connection:
        @contextmanager
        def cursor(self):
            accessed.set()
            yield self

        def executemany(self, *_args):
            pass

    store = object.__new__(PostgresEventStore)
    store._conn = Connection()
    store._lock = threading.RLock()

    def write():
        started.set()
        store.add_tamper([TamperEvent(devid="pc", at=current_hour(), kind="hosts_restored", detail="")])

    with store._lock:
        thread = threading.Thread(target=write)
        thread.start()
        assert started.wait(1)
        joined_transaction = accessed.wait(0.1)
    thread.join(timeout=1)
    assert not thread.is_alive()
    assert not joined_transaction
    assert accessed.is_set()


def test_old_agents_cannot_fetch_or_successfully_acknowledge_new_policy_actions():
    store = InMemoryEventStore()
    client, administrator = panel(store)
    device = client.post("/fct/api/public/v1/register/", json={"devid": "old-pc"}).json()
    auth = {"Authorization": f"Bearer {device['device_token']}"}
    published = client.post("/api/v1/profiles/Default", headers=administrator, json={"web_filter": {
        "category_actions": {"games": "monitor"},
    }}).json()
    assert "version" in published
    assert client.get("/fct/api/public/v1/config/assigned/", headers=auth,
                      params={"client_id": device["client_id"]}).status_code == 409
    acknowledgement = {"client_id": device["client_id"], "version": published["version"],
                       "vdom": "Default", "digest": published["digest"], "success": True}
    assert client.post("/fct/api/public/v1/config/ack/", headers=auth, json=acknowledgement).status_code == 409
    assert client.post("/fct/api/public/v1/host_tags/", headers=auth, json={
        "client_id": device["client_id"], "tags": ["web-filter:actions", "web-filter:monitor",
                                                       "web-filter:categories", "web-filter:dns"],
    }).status_code == 200
    assert client.get("/fct/api/public/v1/config/assigned/", headers=auth,
                      params={"client_id": device["client_id"]}).status_code == 200
    assert client.post("/fct/api/public/v1/config/ack/", headers=auth, json=acknowledgement).status_code == 200


def test_postgres_actions_batches_and_upgrade(database):  # noqa: F811 - imported pytest fixture
    import psycopg

    from app.events import PostgresEventStore
    from app.migrations import apply_migrations

    # Begin at the legacy table and ensure migration preserves its counts.
    with psycopg.connect(database) as conn:
        conn.execute("CREATE TABLE block_events (devid TEXT NOT NULL, hour TIMESTAMPTZ NOT NULL, "
                     "domain TEXT NOT NULL, reason TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', "
                     "count BIGINT NOT NULL CHECK(count>0), PRIMARY KEY(devid,hour,domain,reason,category))")
        conn.execute("INSERT INTO block_events VALUES ('legacy',%s,'legacy.example','rule','',3)", (current_hour(),))
    apply_migrations(database)
    store = PostgresEventStore(database)
    try:
        now = current_hour()
        common = {"devid": "pc", "hour": now, "domain": "same.example", "reason": "category", "category": "games"}
        store.add([BlockEvent(**common, count=2), BlockEvent(**common, count=9, action="monitored")])
        assert store.daily_totals(now) == {now.date(): 5}
        assert store.daily_totals(now, action="monitored") == {now.date(): 9}
        item = BlockEvent(**common, count=4, action="monitored")
        assert store.add_batch("pc", "b" * 64, [item], "c" * 64) is True
        assert store.add_batch("pc", "b" * 64, [item], "c" * 64) is False
        with pytest.raises(ValueError, match="batch"):
            store.add_batch("pc", "b" * 64, [item], "d" * 64)
        assert store.daily_totals(now, action="monitored") == {now.date(): 13}
    finally:
        store.close()
