"""Persistent tenant IdP trust configuration; certificate access stays server-side."""

from __future__ import annotations

from dataclasses import replace
from threading import Lock
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .saml import IdpConfig


class IdpStore(Protocol):
    def put(self, prefix: str, idp: IdpConfig) -> None: ...
    def get(self, prefix: str) -> IdpConfig | None: ...


class InMemoryIdpStore:
    def __init__(self) -> None:
        self._idps: dict[str, IdpConfig] = {}
        self._lock = Lock()

    def put(self, prefix: str, idp: IdpConfig) -> None:
        with self._lock:
            self._idps[prefix] = replace(idp)

    def get(self, prefix: str) -> IdpConfig | None:
        with self._lock:
            idp = self._idps.get(prefix)
            return replace(idp) if idp is not None else None


class PostgresIdpStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS saml_idps (
                prefix TEXT PRIMARY KEY, entity_id TEXT NOT NULL,
                sso_url TEXT NOT NULL, certificate TEXT NOT NULL
            )""")

    def put(self, prefix: str, idp: IdpConfig) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO saml_idps(prefix, entity_id, sso_url, certificate)
                VALUES (%s, %s, %s, %s) ON CONFLICT (prefix) DO UPDATE SET
                entity_id=EXCLUDED.entity_id, sso_url=EXCLUDED.sso_url,
                certificate=EXCLUDED.certificate""",
                (prefix, idp.entity_id, idp.sso_url, idp.certificate or ""),
            )

    def get(self, prefix: str) -> IdpConfig | None:
        from .saml import IdpConfig

        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT entity_id, sso_url, certificate FROM saml_idps WHERE prefix=%s",
                (prefix,),
            )
            row = cur.fetchone()
        return IdpConfig(*row) if row is not None else None
