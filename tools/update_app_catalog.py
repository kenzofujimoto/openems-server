#!/usr/bin/env python3
"""Refresh the application catalog from the public winget source index.

Downloads the winget source2.msix over HTTPS, extracts only Public/index.db and publishes
app-catalog.json atomically. A failed run keeps the last publication.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.app_catalog import SOURCE_URL, build_catalog  # noqa: E402
from tools.update_categories import _require_https, fetch_archive, run_periodically  # noqa: E402

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_INDEX_BYTES = 256 * 1024 * 1024
INDEX = "Public/index.db"


def extract_index(package: Path, work: Path, *, max_bytes: int = MAX_INDEX_BYTES) -> Path:
    """Copy only the index database out of the package, refusing unsafe or oversized members."""
    with zipfile.ZipFile(package) as bundle:
        for name in bundle.namelist():
            if name.startswith(("/", "\\")) or ".." in Path(name).parts or ":" in name:
                raise ValueError(f"unsafe member in winget package: {name}")
        try:
            member = bundle.getinfo(INDEX)
        except KeyError as error:
            raise ValueError(f"winget package has no {INDEX}") from error
        if member.file_size > max_bytes:
            raise ValueError(f"winget index is larger than {max_bytes} bytes")
        work.mkdir(parents=True, exist_ok=True)
        target = work / "index.db"
        with bundle.open(member) as source, target.open("wb") as output:
            shutil.copyfileobj(source, output)
    return target


def update(package: Path, output: Path, work: Path) -> dict[str, Any]:
    return build_catalog(extract_index(package, work), output, now=datetime.now(UTC))


def _report(manifest: dict[str, Any]) -> int:
    for category in manifest["categories"]:
        print(f"{category['id']:14} {category['apps']:>6} apps", flush=True)
    print(f"{len(manifest['apps'])} applications published", flush=True)
    return 0 if manifest["apps"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="OPENEMS_APP_CATALOG_DIR directory")
    parser.add_argument("--url", default=SOURCE_URL, help="HTTPS address of the winget source2.msix")
    parser.add_argument("--every-hours", type=float, help="keep running and refresh at this interval")
    args = parser.parse_args()
    try:
        _require_https(args.url)
    except ValueError as error:
        parser.error(str(error))

    def job() -> int:
        with tempfile.TemporaryDirectory(prefix="openems-winget-") as scratch:
            downloaded = fetch_archive(args.url, Path(scratch) / "source2.msix", max_bytes=MAX_DOWNLOAD_BYTES)
            return _report(update(downloaded, args.output, Path(scratch) / "work"))

    if args.every_hours is None:
        return job()
    if args.every_hours <= 0:
        parser.error("--every-hours must be positive")
    run_periodically(job, args.every_hours * 3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
