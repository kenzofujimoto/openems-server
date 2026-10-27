"""Web category publication: build hashed category files from UT1 lists and serve them to agents."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent.categories import build_category_file
from agent.policy import CATEGORIES

ATTRIBUTION = ("Category lists: Université Toulouse Capitole (UT1 blacklists, Fabrice Prigent), "
               "licensed CC BY-SA 4.0. Hashed and regrouped by openems.")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EMPTY: dict[str, Any] = {"version": None, "attribution": "", "categories": []}
TAXONOMY_VERSION = "openems-ut1-" + hashlib.sha256(
    json.dumps(CATEGORIES, sort_keys=True, ensure_ascii=False).encode("utf-8")
).hexdigest()[:16]
SOURCE = {"id": "ut1", "homepage": "https://dsi.ut-capitole.fr/blacklists/"}


def missing_category_health(*, now: datetime | None = None, max_age_hours: int = 48) -> dict[str, Any]:
    """An absent publication is unavailable classification, not proof that sites are unclassified."""
    checked = datetime.now(UTC) if now is None else now
    if checked.tzinfo is None or checked.utcoffset() is None:
        raise ValueError("category health requires a timezone-aware timestamp")
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 8760:
        raise ValueError("category maximum age must be an integer between 1 and 8760 hours")
    return {
        "status": "missing", "published_at": None, "age_seconds": None, "stale": None,
        "max_age_hours": max_age_hours, "checked_at": checked.astimezone(UTC).isoformat(),
        "taxonomy_version": TAXONOMY_VERSION, "source": dict(SOURCE), "error": None,
    }


def _write_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".openems-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _domains(paths: list[Path]) -> Iterator[str]:
    for path in paths:
        with path.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    yield entry


def build_categories(source: Path, output: Path, *, now: datetime) -> dict[str, Any]:
    """Build every category that has at least one UT1 list under `source` (UT1 layout: <list>/domains)."""
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for category, entry in CATEGORIES.items():
        present = [name for name in entry["sources"] if (source / name / "domains").is_file()]
        if not present:
            continue
        data = build_category_file(_domains([source / name / "domains" for name in present]))
        digest = hashlib.sha256(data).hexdigest()
        _write_atomic(output / f"{category}-{digest}.bin", data)
        entries.append({"id": category, "label": entry["label"], "group": entry["group"], "sources": present,
                        "count": (len(data) - 12) // 8, "digest": digest, "size": len(data)})
    manifest = {"version": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "attribution": ATTRIBUTION, "categories": entries}
    # The manifest switches agents to the new files atomically; stale files go only afterwards.
    _write_atomic(output / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
    published = {f"{entry['id']}-{entry['digest']}.bin" for entry in entries}
    for stale in output.glob("*.bin"):
        if stale.name not in published:
            stale.unlink()
    return manifest


class CategoryRepository:
    """Read side for the agent routes; serves only files named in the current manifest."""

    def __init__(self, directory: Path):
        self._directory = directory

    def manifest(self) -> dict[str, Any]:
        path = self._directory / "manifest.json"
        if not path.is_file():
            return dict(_EMPTY)
        return json.loads(path.read_text(encoding="utf-8"))

    def health(self, *, now: datetime | None = None, max_age_hours: int = 48) -> dict[str, Any]:
        """Inspect publication metadata without changing the device manifest or deleting stale data."""
        checked = datetime.now(UTC) if now is None else now
        health = missing_category_health(now=checked, max_age_hours=max_age_hours)
        if not (self._directory / "manifest.json").is_file():
            return health
        try:
            manifest = self.manifest()
            if not isinstance(manifest, dict) or not isinstance(manifest.get("version"), str):
                raise TypeError("invalid publication shape")
            if not isinstance(manifest.get("attribution"), str) or not manifest["attribution"].strip():
                raise ValueError("invalid publication attribution")
            published = datetime.fromisoformat(manifest["version"])
            if published.tzinfo is None or published.utcoffset() is None:
                raise ValueError("publication requires a timezone")
            age = (checked - published).total_seconds()
            if age < 0:
                raise ValueError("publication is in the future")
            entries = manifest.get("categories")
            if not isinstance(entries, list) or any(
                not isinstance(entry, dict) or entry.get("id") not in CATEGORIES
                or type(entry.get("count")) is not int or entry["count"] < 0
                or any(not isinstance(entry.get(field), str) or not entry[field].strip()
                       or len(entry[field]) > 256 for field in ("label", "group")) for entry in entries
            ):
                raise ValueError("invalid publication categories")
            if len({entry["id"] for entry in entries}) != len(entries):
                raise ValueError("duplicate publication categories")
            stale = age > max_age_hours * 3600
            empty = not any(entry["count"] > 0 for entry in entries)
            health.update({
                "status": "empty" if empty else "stale" if stale else "current",
                "published_at": published.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "age_seconds": int(age), "stale": stale,
            })
        except (OSError, ValueError, TypeError):
            # Return a bounded diagnostic, never local paths or malformed publication content.
            health.update({"status": "invalid", "error": "invalid_publication"})
        return health

    def file(self, category: str, digest: str) -> bytes | None:
        if category not in CATEGORIES or not _DIGEST.fullmatch(digest):
            return None
        listed = any(entry.get("id") == category and entry.get("digest") == digest
                     for entry in self.manifest().get("categories", []))
        path = self._directory / f"{category}-{digest}.bin"
        if not listed or not path.is_file():
            return None
        data = path.read_bytes()
        # Never serve a file that no longer matches its published digest.
        return data if hashlib.sha256(data).hexdigest() == digest else None
