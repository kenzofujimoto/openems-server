"""Audit log of administrative actions.

Records who did what: publishing a profile, adding or removing an assignment
rule, etc. `InMemoryAuditLog` is the default; `PostgresAuditLog` persists to an
``audit_log`` table. Same port/contract pattern as the stores and queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class AuditEntry:
    actor: str                       # admin username (or "setup" before auth is on)
    action: str                      # e.g. "profile.publish", "rule.add", "rule.remove"
    target: str = ""                 # the vdom / rule id acted on
    metadata: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=_utcnow)


@runtime_checkable
class AuditLog(Protocol):
    def record(self, entry: AuditEntry) -> None: ...
    def list(self, limit: int = 100) -> list[AuditEntry]: ...  # newest first


class InMemoryAuditLog:
    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def list(self, limit: int = 100) -> list[AuditEntry]:
        return list(reversed(self._entries))[:limit]


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id       BIGSERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""


class PostgresAuditLog:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._Jsonb = Jsonb
        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(AUDIT_SCHEMA)

    def record(self, entry: AuditEntry) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (ts, actor, action, target, metadata) "
                "VALUES (%s, %s, %s, %s, %s)",
                (entry.ts, entry.actor, entry.action, entry.target, self._Jsonb(entry.metadata)),
            )

    def list(self, limit: int = 100) -> list[AuditEntry]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT ts, actor, action, target, metadata FROM audit_log "
                "ORDER BY id DESC LIMIT %s",
                (limit,),
            )
            return [
                AuditEntry(
                    actor=r[1], action=r[2], target=r[3],
                    metadata=dict(r[4]) if r[4] else {}, ts=r[0],
                )
                for r in cur.fetchall()
            ]

    def close(self) -> None:
        self._conn.close()
