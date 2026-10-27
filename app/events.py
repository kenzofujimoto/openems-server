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

REASONS = ("rule", "category", "doh", "policy")
# Protections an agent found altered and restored (tamper-protection.md, decision 4).
TAMPER_KINDS = ("dns_rule_restored", "wfp_restored", "browser_policy_restored", "hosts_restored",
                "service_config_restored", "watchdog_restored", "service_started_by_watchdog", "unexpected_exit",
                "uninstall_code_rejected", "uninstall_without_secret")
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
    action: str = "blocked"
    source: str = "dns"


@dataclass(frozen=True, slots=True)
class TamperEvent:
    devid: str
    at: datetime
    kind: str              # one of TAMPER_KINDS, or "dropped"
    detail: str


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
    action, source = row.action, row.source
    if row.reason not in REASONS or source != "dns" or action not in ("blocked", "monitored"):
        return None
    if action == "blocked" and row.reason == "policy" or action == "monitored" and row.reason == "doh":
        return None
    return BlockEvent(devid=devid, hour=hour, domain=domain, reason=row.reason, category=category,
                      count=row.count, action=action, source=source)


def parse_tamper(devid: str, row: Any, *, now: datetime, retention_days: int) -> TamperEvent | None:
    """One uploaded tamper row as a stored event, or None when it must be skipped."""
    try:
        at = datetime.fromisoformat(row.at)
    except ValueError:
        return None
    if at.tzinfo is None:
        return None
    at = at.astimezone(UTC)
    if not now - timedelta(days=retention_days) <= at <= now + FUTURE_TOLERANCE:
        return None
    return TamperEvent(devid=devid, at=at, kind=row.kind, detail=row.detail)


@runtime_checkable
class EventStore(Protocol):
    def add(self, events: list[BlockEvent]) -> None: ...          # counts sum per (devid, hour, domain, reason, category)
    def purge(self, before: datetime) -> int: ...                 # removes rows with hour < before
    def recent(self, limit: int, *, action: str | None = None) -> list[BlockEvent]: ...
    def daily_totals(self, since: datetime, *, action: str = "blocked") -> dict[date, int]: ...
    def add_batch(self, devid: str, batch_id: str, events: list[BlockEvent], fingerprint: str) -> bool: ...
    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]: ...
    def add_tamper(self, events: list[TamperEvent]) -> None: ...
    def purge_tamper(self, before: datetime) -> int: ...
    def recent_tamper(self, limit: int) -> list[TamperEvent]: ...    # newest first


def _key(event: BlockEvent) -> tuple[str, datetime, str, str, str, str, str]:
    return event.devid, event.hour, event.domain, event.reason, event.category, event.action, event.source


class InMemoryEventStore:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, datetime, str, str, str, str, str], int] = {}
        self._batches: dict[tuple[str, str], tuple[str, datetime]] = {}
        self._tamper: list[TamperEvent] = []
        self._lock = threading.Lock()

    def add_tamper(self, events: list[TamperEvent]) -> None:
        with self._lock:
            self._tamper.extend(events)

    def purge_tamper(self, before: datetime) -> int:
        with self._lock:
            kept = [event for event in self._tamper if event.at >= before]
            removed, self._tamper = len(self._tamper) - len(kept), kept
            return removed

    def recent_tamper(self, limit: int) -> list[TamperEvent]:
        with self._lock:
            return sorted(self._tamper, key=lambda event: event.at, reverse=True)[:limit]

    def add(self, events: list[BlockEvent]) -> None:
        with self._lock:
            for event in events:
                self._counts[_key(event)] = self._counts.get(_key(event), 0) + event.count

    def add_batch(self, devid: str, batch_id: str, events: list[BlockEvent], fingerprint: str) -> bool:
        with self._lock:
            existing = self._batches.get((devid, batch_id))
            if existing is not None:
                if existing[0] != fingerprint:
                    raise ValueError("batch id already belongs to a different payload")
                return False
            if len(self._batches) >= 100_000:
                raise OverflowError("web event batch receipt limit reached")
            for event in events:
                self._counts[_key(event)] = self._counts.get(_key(event), 0) + event.count
            self._batches[(devid, batch_id)] = fingerprint, datetime.now(UTC)
            return True

    def purge(self, before: datetime) -> int:
        with self._lock:
            expired = [key for key in self._counts if key[1] < before]
            for key in expired:
                del self._counts[key]
            self._batches = {key: value for key, value in self._batches.items() if value[1] >= before}
            return len(expired)

    def _events(self) -> list[BlockEvent]:
        with self._lock:
            return [BlockEvent(devid=key[0], hour=key[1], domain=key[2], reason=key[3], category=key[4],
                               count=count, action=key[5], source=key[6])
                    for key, count in self._counts.items()]

    def recent(self, limit: int, *, action: str | None = None) -> list[BlockEvent]:
        events = sorted((event for event in self._events() if action is None or event.action == action),
                        key=lambda event: (-event.hour.timestamp(), -event.count, event.domain))
        return events[:limit]

    def daily_totals(self, since: datetime, *, action: str = "blocked") -> dict[date, int]:
        totals: dict[date, int] = {}
        for event in self._events():
            matches = event.reason == "dropped" if action == "dropped" else event.action == action and event.reason != "dropped"
            if event.hour >= since and matches:
                day = event.hour.astimezone(UTC).date()
                totals[day] = totals.get(day, 0) + event.count
        return totals

    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]:
        totals: dict[str, int] = {}
        for event in self._events():
            if event.hour >= since and event.reason != "dropped" and event.action == "blocked":
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
ALTER TABLE block_events ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'blocked'
    CHECK (action IN ('blocked', 'monitored'));
ALTER TABLE block_events ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'dns'
    CHECK (source IN ('dns'));
ALTER TABLE block_events DROP CONSTRAINT IF EXISTS block_events_pkey;
ALTER TABLE block_events ADD PRIMARY KEY (devid, hour, domain, reason, category, action, source);
CREATE TABLE IF NOT EXISTS web_event_batches (
    devid TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (devid, batch_id)
);
CREATE INDEX IF NOT EXISTS idx_web_event_batches_received_at ON web_event_batches (received_at);
"""

TAMPER_SCHEMA = """
CREATE TABLE IF NOT EXISTS tamper_events (
    id     BIGSERIAL PRIMARY KEY,
    devid  TEXT NOT NULL,
    at     TIMESTAMPTZ NOT NULL,
    kind   TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tamper_events_at ON tamper_events (at);
"""

_COLUMNS = "devid, hour, domain, reason, category, count, action, source"


class PostgresEventStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._lock = threading.RLock()

    def init_schema(self) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(EVENTS_SCHEMA)
            cur.execute(TAMPER_SCHEMA)

    def add(self, events: list[BlockEvent]) -> None:
        if not events:
            return
        with self._lock, self._conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO block_events ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (devid, hour, domain, reason, category, action, source) "
                "DO UPDATE SET count = block_events.count + EXCLUDED.count",
                [(event.devid, event.hour, event.domain, event.reason, event.category, event.count,
                  event.action, event.source) for event in events],
            )

    def add_batch(self, devid: str, batch_id: str, events: list[BlockEvent], fingerprint: str) -> bool:
        with self._lock, self._conn.transaction():
            with self._lock, self._conn.cursor() as cur:
                cur.execute("INSERT INTO web_event_batches (devid,batch_id,fingerprint) VALUES (%s,%s,%s) "
                            "ON CONFLICT (devid,batch_id) DO NOTHING RETURNING batch_id",
                            (devid, batch_id, fingerprint))
                if cur.fetchone() is None:
                    cur.execute("SELECT fingerprint FROM web_event_batches WHERE devid=%s AND batch_id=%s",
                                (devid, batch_id))
                    existing = cur.fetchone()
                    if existing is None or existing[0] != fingerprint:
                        raise ValueError("batch id already belongs to a different payload")
                    return False
            self.add(events)
        return True

    def purge(self, before: datetime) -> int:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("DELETE FROM web_event_batches WHERE received_at < %s", (before,))
            cur.execute("DELETE FROM block_events WHERE hour < %s", (before,))
            return cur.rowcount

    def recent(self, limit: int, *, action: str | None = None) -> list[BlockEvent]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute(f"SELECT {_COLUMNS} FROM block_events WHERE (%s::text IS NULL OR action=%s) "
                        "ORDER BY hour DESC, count DESC, domain LIMIT %s", (action, action, limit))
            return [BlockEvent(devid=r[0], hour=r[1].astimezone(UTC), domain=r[2], reason=r[3], category=r[4],
                               count=r[5], action=r[6], source=r[7])
                    for r in cur.fetchall()]

    def daily_totals(self, since: datetime, *, action: str = "blocked") -> dict[date, int]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT (hour AT TIME ZONE 'UTC')::date, sum(count) FROM block_events "
                        "WHERE hour >= %s AND ((%s='dropped' AND reason='dropped') "
                        "OR (action=%s AND reason<>'dropped')) GROUP BY 1", (since, action, action))
            return {row[0]: int(row[1]) for row in cur.fetchall()}

    def top_domains(self, since: datetime, limit: int) -> list[tuple[str, int]]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT domain, sum(count) AS total FROM block_events WHERE hour >= %s "
                        "AND reason <> 'dropped' AND action='blocked' "
                        "GROUP BY domain ORDER BY total DESC, domain LIMIT %s", (since, limit))
            return [(row[0], int(row[1])) for row in cur.fetchall()]

    def add_tamper(self, events: list[TamperEvent]) -> None:
        if not events:
            return
        with self._lock, self._conn.cursor() as cur:
            cur.executemany("INSERT INTO tamper_events (devid, at, kind, detail) VALUES (%s, %s, %s, %s)",
                            [(event.devid, event.at, event.kind, event.detail) for event in events])

    def purge_tamper(self, before: datetime) -> int:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("DELETE FROM tamper_events WHERE at < %s", (before,))
            return cur.rowcount

    def recent_tamper(self, limit: int) -> list[TamperEvent]:
        with self._lock, self._conn.cursor() as cur:
            cur.execute("SELECT devid, at, kind, detail FROM tamper_events ORDER BY at DESC, id DESC LIMIT %s", (limit,))
            return [TamperEvent(devid=r[0], at=r[1].astimezone(UTC), kind=r[2], detail=r[3]) for r in cur.fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
