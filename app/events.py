"""Block log: hourly aggregates of blocked DNS answers reported by agents.

Rows are personal data of whoever uses each machine (LGPD): no user names are
accepted, rows expire after the configured retention and only panel roles with
read permission see them. `InMemoryEventStore` is the default;
`PostgresEventStore` persists to the ``block_events`` table.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from agent.policy import CATEGORIES, normalize_domain

REASONS = ("rule", "category", "doh")
DEFAULT_RETENTION_DAYS = 30
# Agent clocks may run slightly ahead; anything later is refused.
FUTURE_TOLERANCE = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class BlockEvent:
    devid: str
    hour: datetime
    domain: str            # empty for "dropped" rows
    reason: str            # rule | category | doh | dropped
    category: str          # empty unless reason == "category"
    count: int


def current_hour(now: datetime | None = None) -> datetime:
    return (now or datetime.now(UTC)).astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def validate_retention(days: int) -> int:
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365:
        raise ValueError("block log retention must be between 1 and 365 days")
    return days


def parse_row(devid: str, row: Any, *, now: datetime, retention_days: int) -> BlockEvent | None:
    """One uploaded row as a stored event, or None when it must be skipped."""
    try:
        hour = datetime.fromisoformat(row.hour)
    except ValueError:
        return None
    if hour.tzinfo is None or (hour.minute, hour.second, hour.microsecond) != (0, 0, 0):
        return None
    hour = hour.astimezone(UTC)
    if not current_hour(now) - timedelta(days=retention_days) <= hour <= now + FUTURE_TOLERANCE:
        return None
    try:
        domain = normalize_domain(row.domain.removesuffix("."))
    except ValueError:
        return None
    category = row.category or ""
    if (row.reason == "category") != bool(category) or (category and category not in CATEGORIES):
        return None
    return BlockEvent(devid=devid, hour=hour, domain=domain, reason=row.reason, category=category, count=row.count)


@runtime_checkable
class EventStore(Protocol):
    def add(self, events: list[BlockEvent]) -> None: ...          # counts sum per (devid, hour, domain, reason, category)
    def purge(self, before: datetime) -> int: ...                 # removes rows with hour < before
    def recent(self, limit: int) -> list[BlockEvent]: ...         # newest hour first, then highest count
    def daily_totals(self, since: datetime) -> dict[date, int]: ...   # UTC days, dropped rows included
    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]: ...


def _key(event: BlockEvent) -> tuple[str, datetime, str, str, str]:
    return event.devid, event.hour, event.domain, event.reason, event.category


class InMemoryEventStore:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, datetime, str, str, str], int] = {}
        self._lock = threading.Lock()

    def add(self, events: list[BlockEvent]) -> None:
        with self._lock:
            for event in events:
                self._counts[_key(event)] = self._counts.get(_key(event), 0) + event.count

    def purge(self, before: datetime) -> int:
        with self._lock:
            expired = [key for key in self._counts if key[1] < before]
            for key in expired:
                del self._counts[key]
            return len(expired)

    def _events(self) -> list[BlockEvent]:
        with self._lock:
            return [BlockEvent(devid=key[0], hour=key[1], domain=key[2], reason=key[3], category=key[4], count=count)
                    for key, count in self._counts.items()]

    def recent(self, limit: int) -> list[BlockEvent]:
        events = sorted(self._events(), key=lambda event: (-event.hour.timestamp(), -event.count, event.domain))
        return events[:limit]

    def daily_totals(self, since: datetime) -> dict[date, int]:
        totals: dict[date, int] = {}
        for event in self._events():
            if event.hour >= since:
                day = event.hour.astimezone(UTC).date()
                totals[day] = totals.get(day, 0) + event.count
        return totals

    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]:
        totals: dict[str, int] = {}
        for event in self._events():
            if event.hour >= since and event.reason != "dropped":
                totals[event.domain] = totals.get(event.domain, 0) + event.count
        return sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:limit]


EVENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS block_events (
    devid    TEXT NOT NULL,
    hour     TIMESTAMPTZ NOT NULL,
    domain   TEXT NOT NULL,
    reason   TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    count    BIGINT NOT NULL CHECK (count > 0),
    PRIMARY KEY (devid, hour, domain, reason, category)
);
CREATE INDEX IF NOT EXISTS idx_block_events_hour ON block_events (hour);
"""

_COLUMNS = "devid, hour, domain, reason, category, count"


class PostgresEventStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(EVENTS_SCHEMA)

    def add(self, events: list[BlockEvent]) -> None:
        if not events:
            return
        with self._conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO block_events ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (devid, hour, domain, reason, category) "
                "DO UPDATE SET count = block_events.count + EXCLUDED.count",
                [(event.devid, event.hour, event.domain, event.reason, event.category, event.count) for event in events],
            )

    def purge(self, before: datetime) -> int:
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM block_events WHERE hour < %s", (before,))
            return cur.rowcount

    def recent(self, limit: int) -> list[BlockEvent]:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {_COLUMNS} FROM block_events ORDER BY hour DESC, count DESC, domain LIMIT %s", (limit,))
            return [BlockEvent(devid=r[0], hour=r[1].astimezone(UTC), domain=r[2], reason=r[3], category=r[4], count=r[5])
                    for r in cur.fetchall()]

    def daily_totals(self, since: datetime) -> dict[date, int]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT (hour AT TIME ZONE 'UTC')::date, sum(count) FROM block_events "
                        "WHERE hour >= %s GROUP BY 1", (since,))
            return {row[0]: int(row[1]) for row in cur.fetchall()}

    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT domain, sum(count) AS total FROM block_events WHERE hour >= %s AND reason <> 'dropped' "
                        "GROUP BY domain ORDER BY total DESC, domain LIMIT %s", (since, limit))
            return [(row[0], int(row[1])) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
