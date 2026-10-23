"""Web category publication: build hashed category files from UT1 lists and serve them to agents."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from agent.categories import build_category_file
from agent.policy import CATEGORIES

ATTRIBUTION = ("Category lists: Université Toulouse Capitole (UT1 blacklists, Fabrice Prigent), "
               "licensed CC BY-SA 4.0. Hashed and regrouped by openems.")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EMPTY: dict[str, Any] = {"version": None, "attribution": "", "categories": []}


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
