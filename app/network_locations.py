"""Persistent network-location definitions and group-to-inside-policy mappings (F6)."""

from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import Any, Protocol


class LocationStore(Protocol):
    def locations(self) -> list[dict[str, Any]]: ...
    def create(self, location: dict[str, Any]) -> bool: ...
    def update(self, location: dict[str, Any]) -> bool: ...
    def remove(self, location_id: str) -> bool: ...
    def mappings(self) -> list[dict[str, str]]: ...
    def set_mapping(self, vdom: str, location_id: str, inside_vdom: str) -> None: ...
    def remove_mapping(self, vdom: str, location_id: str) -> bool: ...


class InMemoryLocationStore:
    def __init__(self) -> None:
        self._locations: dict[str, dict[str, Any]] = {}
        self._mappings: dict[tuple[str, str], str] = {}
        self._lock = RLock()

    def locations(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(sorted(self._locations.values(), key=lambda item: (item["name"].casefold(), item["id"])))

    def create(self, location: dict[str, Any]) -> bool:
        with self._lock:
            if location["id"] in self._locations:
                return False
            self._locations[location["id"]] = deepcopy(location)
            return True

    def update(self, location: dict[str, Any]) -> bool:
        with self._lock:
            if location["id"] not in self._locations:
                return False
            self._locations[location["id"]] = deepcopy(location)
            return True

    def remove(self, location_id: str) -> bool:
        with self._lock:
            if self._locations.pop(location_id, None) is None:
                return False
            self._mappings = {key: value for key, value in self._mappings.items() if key[1] != location_id}
            return True

    def mappings(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"vdom": vdom, "location_id": location, "inside_vdom": inside}
                    for (vdom, location), inside in sorted(self._mappings.items())]

    def set_mapping(self, vdom: str, location_id: str, inside_vdom: str) -> None:
        with self._lock:
            if location_id not in self._locations:
                raise ValueError("unknown location")
            self._mappings[vdom, location_id] = inside_vdom

    def remove_mapping(self, vdom: str, location_id: str) -> bool:
        with self._lock:
            return self._mappings.pop((vdom, location_id), None) is not None


SCHEMA = """
CREATE TABLE IF NOT EXISTS network_locations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    definition JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS location_policies (
    vdom TEXT NOT NULL,
    location_id TEXT NOT NULL REFERENCES network_locations(id) ON DELETE CASCADE,
    inside_vdom TEXT NOT NULL,
    PRIMARY KEY (vdom, location_id)
);
"""


class PostgresLocationStore:
    def __init__(self, dsn: str) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._Jsonb = Jsonb

    def init_schema(self) -> None:
        self._conn.execute(SCHEMA)

    def locations(self) -> list[dict[str, Any]]:
        with self._conn.cursor() as cursor:
            cursor.execute("SELECT definition FROM network_locations")
            return sorted((dict(row[0]) for row in cursor.fetchall()), key=lambda item: (item["name"].casefold(), item["id"]))

    def create(self, location: dict[str, Any]) -> bool:
        with self._conn.cursor() as cursor:
            cursor.execute("INSERT INTO network_locations (id, name, definition) VALUES (%s, %s, %s) "
                           "ON CONFLICT (id) DO NOTHING", (location["id"], location["name"], self._Jsonb(location)))
            return cursor.rowcount == 1

    def update(self, location: dict[str, Any]) -> bool:
        with self._conn.cursor() as cursor:
            cursor.execute("UPDATE network_locations SET name = %s, definition = %s WHERE id = %s",
                           (location["name"], self._Jsonb(location), location["id"]))
            return cursor.rowcount == 1

    def remove(self, location_id: str) -> bool:
        with self._conn.cursor() as cursor:
            cursor.execute("DELETE FROM network_locations WHERE id = %s", (location_id,))
            return cursor.rowcount == 1

    def mappings(self) -> list[dict[str, str]]:
        with self._conn.cursor() as cursor:
            cursor.execute("SELECT vdom, location_id, inside_vdom FROM location_policies ORDER BY vdom, location_id")
            return [{"vdom": row[0], "location_id": row[1], "inside_vdom": row[2]} for row in cursor.fetchall()]

    def set_mapping(self, vdom: str, location_id: str, inside_vdom: str) -> None:
        import psycopg

        try:
            self._conn.execute("INSERT INTO location_policies (vdom, location_id, inside_vdom) VALUES (%s, %s, %s) "
                               "ON CONFLICT (vdom, location_id) DO UPDATE SET inside_vdom = EXCLUDED.inside_vdom",
                               (vdom, location_id, inside_vdom))
        except psycopg.errors.ForeignKeyViolation as error:
            raise ValueError("unknown location") from error

    def remove_mapping(self, vdom: str, location_id: str) -> bool:
        with self._conn.cursor() as cursor:
            cursor.execute("DELETE FROM location_policies WHERE vdom = %s AND location_id = %s", (vdom, location_id))
            return cursor.rowcount == 1

    def close(self) -> None:
        self._conn.close()
