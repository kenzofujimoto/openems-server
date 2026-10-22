"""Hashed enrollment invitations with atomic, scoped and finite consumption."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from threading import Lock
from typing import Protocol


class EnrollmentStore(Protocol):
    def add(self, token: str, vdom: str, max_uses: int, expires_at: datetime) -> None: ...
    def consume(self, token: str, vdom: str) -> bool: ...


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class InMemoryEnrollmentStore:
    def __init__(self) -> None:
        self._invitations: dict[str, tuple[str, int, datetime]] = {}
        self._lock = Lock()

    def add(self, token: str, vdom: str, max_uses: int, expires_at: datetime) -> None:
        if not token or not vdom or max_uses < 1 or expires_at.tzinfo is None:
            raise ValueError("Invalid invitation scope, usage limit or expiry")
        with self._lock:
            self._invitations.setdefault(_hash(token), (vdom, max_uses, expires_at))

    def consume(self, token: str, vdom: str) -> bool:
        with self._lock:
            invitation = self._invitations.get(_hash(token))
            if invitation is None:
                return False
            scope, remaining, expiry = invitation
            if scope != vdom or remaining < 1 or expiry <= datetime.now(timezone.utc):
                return False
            self._invitations[_hash(token)] = (scope, remaining - 1, expiry)
            return True


class PostgresEnrollmentStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS enrollment_invitations (
                token_hash TEXT PRIMARY KEY, vdom TEXT NOT NULL,
                max_uses INTEGER NOT NULL CHECK (max_uses > 0),
                used INTEGER NOT NULL DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL
            )""")

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
                WHERE token_hash=%s AND vdom=%s AND used<max_uses AND expires_at>now()
                RETURNING token_hash""", (_hash(token), vdom))
            return cur.fetchone() is not None

    def close(self) -> None:
        self._conn.close()
