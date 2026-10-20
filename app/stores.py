"""Storage backends for the endpoint-management server.

`Store` is the port; `InMemoryStore` is the default (tests, first bring-up) and
`PostgresStore` is the production backend. Both satisfy the same contract, which
is exercised by tests/test_store_contract.py.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import Endpoint, EndpointStatus


@runtime_checkable
class Store(Protocol):
    def upsert(self, endpoint: Endpoint) -> None: ...
    def get_by_client_id(self, client_id: str) -> Endpoint | None: ...
    def get_by_devid(self, devid: str) -> Endpoint | None: ...
    def all(self) -> list[Endpoint]: ...


class InMemoryStore:
    """Non-persistent store. Fine for tests and a first run."""

    def __init__(self) -> None:
        self._by_client: dict[str, Endpoint] = {}
        self._by_devid: dict[str, Endpoint] = {}

    def upsert(self, endpoint: Endpoint) -> None:
        self._by_client[endpoint.client_id] = endpoint
        self._by_devid[endpoint.devid] = endpoint

    def get_by_client_id(self, client_id: str) -> Endpoint | None:
        return self._by_client.get(client_id)

    def get_by_devid(self, devid: str) -> Endpoint | None:
        return self._by_devid.get(devid)

    def all(self) -> list[Endpoint]:
        return list(self._by_devid.values())


SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    devid       TEXT PRIMARY KEY,
    client_id   TEXT UNIQUE NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    fctver      TEXT NOT NULL DEFAULT '',
    vdom        TEXT NOT NULL DEFAULT 'Default',
    status      TEXT NOT NULL DEFAULT 'registered',
    reg_ip      TEXT NOT NULL DEFAULT '',
    host_tags   JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoints_client_id ON endpoints (client_id);
"""


class PostgresStore:
    """PostgreSQL-backed store using psycopg 3.

    Pass a libpq DSN, e.g. "postgresql://user:pass@localhost:5432/openems".
    Call init_schema() once at startup.
    """

    def __init__(self, dsn: str) -> None:
        import psycopg  # imported lazily so the package stays optional
        from psycopg.types.json import Jsonb

        self._psycopg = psycopg
        self._Jsonb = Jsonb
        self._conn = psycopg.connect(dsn, autocommit=True)

    def init_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(SCHEMA)

    def upsert(self, endpoint: Endpoint) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO endpoints
                    (devid, client_id, hostname, os, fctver, vdom, status,
                     reg_ip, host_tags, last_seen, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (devid) DO UPDATE SET
                    client_id = EXCLUDED.client_id,
                    hostname  = EXCLUDED.hostname,
                    os        = EXCLUDED.os,
                    fctver    = EXCLUDED.fctver,
                    vdom      = EXCLUDED.vdom,
                    status    = EXCLUDED.status,
                    reg_ip    = EXCLUDED.reg_ip,
                    host_tags = EXCLUDED.host_tags,
                    last_seen = EXCLUDED.last_seen
                """,
                (
                    endpoint.devid,
                    endpoint.client_id,
                    endpoint.hostname,
                    endpoint.os,
                    endpoint.fctver,
                    endpoint.vdom,
                    endpoint.status.value,
                    endpoint.reg_ip,
                    self._Jsonb(endpoint.host_tags),
                    endpoint.last_seen,
                    endpoint.created_at,
                ),
            )

    def get_by_client_id(self, client_id: str) -> Endpoint | None:
        return self._one("WHERE client_id = %s", (client_id,))

    def get_by_devid(self, devid: str) -> Endpoint | None:
        return self._one("WHERE devid = %s", (devid,))

    def all(self) -> list[Endpoint]:
        with self._conn.cursor() as cur:
            cur.execute(self._SELECT)
            return [self._row(r) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()

    # --- internals ------------------------------------------------------

    _SELECT = (
        "SELECT devid, client_id, hostname, os, fctver, vdom, status, reg_ip, "
        "host_tags, last_seen, created_at FROM endpoints "
    )

    def _one(self, where: str, params: tuple[object, ...]) -> Endpoint | None:
        with self._conn.cursor() as cur:
            cur.execute(self._SELECT + where, params)
            row = cur.fetchone()
            return self._row(row) if row else None

    @staticmethod
    def _row(r: tuple[object, ...]) -> Endpoint:
        return Endpoint(
            devid=r[0],
            client_id=r[1],
            hostname=r[2],
            os=r[3],
            fctver=r[4],
            vdom=r[5],
            status=EndpointStatus(r[6]),
            reg_ip=r[7],
            host_tags=list(r[8]) if r[8] else [],
            last_seen=r[9],
            created_at=r[10],
        )
