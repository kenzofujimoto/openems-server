"""Bounded inventory snapshots and idempotent control events with explicit retention."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from threading import RLock
from typing import Any, Protocol


class InventoryStore(Protocol):
    def replace(self, snapshot: dict[str, Any]) -> bool: ...
    def snapshot(self, devid: str) -> dict[str, Any] | None: ...
    def add_events(self, events: list[dict[str, Any]]) -> None: ...
    def recent_events(self, limit: int) -> list[dict[str, Any]]: ...
    def daily_totals(self, since: datetime) -> dict[str, dict[str, int]]: ...
    def purge(self, before: datetime) -> None: ...


def event_identity(event: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class InMemoryInventoryStore:
    def __init__(self) -> None:
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._events: dict[str, dict[str, Any]] = {}
        self._lock = RLock()

    def replace(self, snapshot: dict[str, Any]) -> bool:
        with self._lock:
            previous = self._snapshots.get(snapshot["devid"])
            if previous and datetime.fromisoformat(previous["collected_at"]) > datetime.fromisoformat(snapshot["collected_at"]):
                return False
            self._snapshots[snapshot["devid"]] = deepcopy(snapshot)
            return True

    def snapshot(self, devid: str) -> dict[str, Any] | None:
        with self._lock:
            return deepcopy(self._snapshots.get(devid))

    def add_events(self, events: list[dict[str, Any]]) -> None:
        with self._lock:
            for event in events:
                identity = event_identity(event)
                self._events.setdefault(identity, {**deepcopy(event), "id": identity})

    def recent_events(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(sorted(self._events.values(), key=lambda event: (event["at"], event["id"]), reverse=True)[:limit])

    def daily_totals(self, since: datetime) -> dict[str, dict[str, int]]:
        totals: dict[str, dict[str, int]] = {}
        with self._lock:
            for event in self._events.values():
                if (event["kind"] in {"usb_block", "usb_read_only", "app_block", "app_network_block"}
                        and datetime.fromisoformat(event["at"]) >= since):
                    counts = totals.setdefault(event["at"][:10], {"apps": 0, "usb": 0})
                    counts["usb" if event["kind"].startswith("usb_") else "apps"] += 1
        return totals

    def purge(self, before: datetime) -> None:
        with self._lock:
            self._snapshots = {devid: snapshot for devid, snapshot in self._snapshots.items()
                               if datetime.fromisoformat(snapshot["collected_at"]) >= before}
            self._events = {identity: event for identity, event in self._events.items()
                            if datetime.fromisoformat(event["at"]) >= before}


SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoint_inventory (
    devid TEXT PRIMARY KEY,
    collected_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS control_events (
    id TEXT PRIMARY KEY,
    devid TEXT NOT NULL,
    at TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_events_at ON control_events(at);
CREATE INDEX IF NOT EXISTS idx_endpoint_inventory_collected ON endpoint_inventory(collected_at);
"""


class PostgresInventoryStore:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._Jsonb = Jsonb

    def init_schema(self) -> None:
        self._conn.execute(SCHEMA)

    def replace(self, snapshot: dict[str, Any]) -> bool:
        with self._conn.cursor() as cursor:
            cursor.execute("INSERT INTO endpoint_inventory (devid, collected_at, snapshot) VALUES (%s,%s,%s) "
                           "ON CONFLICT (devid) DO UPDATE SET collected_at=EXCLUDED.collected_at,snapshot=EXCLUDED.snapshot "
                           "WHERE endpoint_inventory.collected_at <= EXCLUDED.collected_at RETURNING devid",
                           (snapshot["devid"], snapshot["collected_at"], self._Jsonb(snapshot)))
            return cursor.fetchone() is not None

    def snapshot(self, devid: str) -> dict[str, Any] | None:
        with self._conn.cursor() as cursor:
            cursor.execute("SELECT snapshot FROM endpoint_inventory WHERE devid=%s", (devid,))
            row = cursor.fetchone()
            return dict(row[0]) if row else None

    def add_events(self, events: list[dict[str, Any]]) -> None:
        with self._conn.cursor() as cursor:
            cursor.executemany("INSERT INTO control_events(id,devid,at,kind,payload) VALUES(%s,%s,%s,%s,%s) "
                               "ON CONFLICT(id) DO NOTHING", [
                                   (event_identity(event), event["devid"], event["at"], event["kind"],
                                    self._Jsonb({**event, "id": event_identity(event)})) for event in events])

    def recent_events(self, limit: int) -> list[dict[str, Any]]:
        with self._conn.cursor() as cursor:
            cursor.execute("SELECT payload FROM control_events ORDER BY at DESC,id DESC LIMIT %s", (limit,))
            return [dict(row[0]) for row in cursor.fetchall()]

    def daily_totals(self, since: datetime) -> dict[str, dict[str, int]]:
        with self._conn.cursor() as cursor:
            cursor.execute("SELECT (at AT TIME ZONE 'UTC')::date, "
                           "count(*) FILTER (WHERE kind IN ('app_block','app_network_block'))," 
                           "count(*) FILTER (WHERE kind IN ('usb_block','usb_read_only')) "
                           "FROM control_events WHERE at >= %s AND kind IN "
                           "('app_block','app_network_block','usb_block','usb_read_only') GROUP BY 1", (since,))
            return {row[0].isoformat(): {"apps": row[1], "usb": row[2]} for row in cursor.fetchall()}

    def purge(self, before: datetime) -> None:
        with self._conn.transaction():
            self._conn.execute("DELETE FROM endpoint_inventory WHERE collected_at < %s", (before,))
            self._conn.execute("DELETE FROM control_events WHERE at < %s", (before,))

    def close(self) -> None:
        self._conn.close()
