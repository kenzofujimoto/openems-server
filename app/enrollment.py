"""Hashed enrollment invitations with atomic, scoped and finite consumption."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol


class EnrollmentStore(Protocol):
    def add(self, token: str, vdom: str, max_uses: int, expires_at: datetime) -> None: ...
    def consume(self, token: str, vdom: str) -> bool: ...
    def list(self) -> list[dict[str, object]]: ...
    def revoke(self, identifier: str) -> bool: ...


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class InMemoryEnrollmentStore:
    def __init__(self) -> None:
        self._invitations: dict[str, tuple[str, int, datetime]] = {}
        self._revoked: set[str] = set()
        self._lock = Lock()

    def add(self, token: str, vdom: str, max_uses: int, expires_at: datetime) -> None:
        if not token or not vdom or max_uses < 1 or expires_at.tzinfo is None:
            raise ValueError("Invalid invitation scope, usage limit or expiry")
        with self._lock:
            identifier = _hash(token)
            if identifier not in self._revoked:
                self._invitations.setdefault(identifier, (vdom, max_uses, expires_at))

    def consume(self, token: str, vdom: str) -> bool:
        with self._lock:
            invitation = self._invitations.get(_hash(token))
            if invitation is None:
                return False
            scope, remaining, expiry = invitation
            if scope != vdom or remaining < 1 or expiry <= datetime.now(UTC):
                return False
            self._invitations[_hash(token)] = (scope, remaining - 1, expiry)
            return True

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            return [{"id": identifier, "vdom": item[0], "remaining": item[1], "expires_at": item[2].isoformat()}
                    for identifier, item in sorted(self._invitations.items())]

    def revoke(self, identifier: str) -> bool:
        with self._lock:
            removed = self._invitations.pop(identifier, None) is not None
            if removed:
                self._revoked.add(identifier)
            return removed


class PostgresEnrollmentStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS enrollment_invitations (
                token_hash TEXT PRIMARY KEY, vdom TEXT NOT NULL,
                max_uses INTEGER NOT NULL CHECK (max_uses > 0),
                used INTEGER NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT false
            )""")
            cur.execute("ALTER TABLE enrollment_invitations ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT false")

    def add(self, token: str, vdom: str, max_uses: int, expires_at: datetime) -> None:
        if not token or not vdom or max_uses < 1 or expires_at.tzinfo is None:
            raise ValueError("Invalid invitation scope, usage limit or expiry")
        with self._conn.cursor() as cur:
            cur.execute("""INSERT INTO enrollment_invitations
                (token_hash, vdom, max_uses, expires_at) VALUES (%s,%s,%s,%s)
                ON CONFLICT (token_hash) DO NOTHING""", (_hash(token), vdom, max_uses, expires_at))

    def consume(self, token: str, vdom: str) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("""UPDATE enrollment_invitations SET used=used+1
                WHERE token_hash=%s AND vdom=%s AND used<max_uses AND expires_at>now() AND NOT revoked
                RETURNING token_hash""", (_hash(token), vdom))
            return cur.fetchone() is not None

    def list(self) -> list[dict[str, object]]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT token_hash,vdom,max_uses-used,expires_at FROM enrollment_invitations WHERE NOT revoked ORDER BY token_hash")
            return [{"id": row[0], "vdom": row[1], "remaining": row[2], "expires_at": row[3].isoformat()}
                    for row in cur.fetchall()]

    def revoke(self, identifier: str) -> bool:
        with self._conn.cursor() as cur:
            cur.execute("UPDATE enrollment_invitations SET revoked=true WHERE token_hash=%s AND NOT revoked", (identifier,))
            return cur.rowcount > 0

    def close(self) -> None:
        self._conn.close()
