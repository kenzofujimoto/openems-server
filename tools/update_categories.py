#!/usr/bin/env python3
"""Rebuild the published web categories from the UT1 lists.

From an extracted tree (for example git clone --depth 1 https://github.com/olbat/ut1-blacklists):
    python tools/update_categories.py ut1-blacklists/blacklists /var/lib/openems/categories
From the published archive, once a day (the docker compose "categories" job):
    python tools/update_categories.py --url https://.../blacklists.tar.gz --every-hours 24 /var/lib/openems/categories
Agents pick up the new manifest at their next synchronization; a failed run keeps the last publication.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The repository root must be importable before the app package.
from app.categories import build_categories

LIST_NAME = re.compile(r"^[a-z0-9_]+$")
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
CHUNK = 1024 * 1024


def _require_https(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("category lists must be downloaded over https, without credentials in the URL")


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_archive(url: str, destination: Path, *, max_bytes: int = MAX_DOWNLOAD_BYTES, timeout: int = 120) -> Path:
    """Download over HTTPS (redirects included) into `destination`, refusing oversized responses."""
    _require_https(url)
    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    received = 0
    with opener.open(url, timeout=timeout) as response, destination.open("wb") as output:
        while chunk := response.read(CHUNK):
            received += len(chunk)
            if received > max_bytes:
                raise ValueError(f"category archive is larger than {max_bytes} bytes")
            output.write(chunk)
    return destination


def _list_name(name: str) -> str | None:
    """List id for a `<...>/<list>/domains` member; other members are ignored. Unsafe paths raise."""
    parts = name.split("/")
    if "\\" in name or name.startswith("/") or ".." in parts:
        raise ValueError(f"unsafe path in category archive: {name!r}")
    if len(parts) < 2 or parts[-1] != "domains":
        return None
    if not LIST_NAME.match(parts[-2]):
        raise ValueError(f"unexpected list name in category archive: {name!r}")
    return parts[-2]


def extract_lists(archive: Path, work: Path, *, max_bytes: int = MAX_EXTRACTED_BYTES) -> Path:
    """Copy only `<list>/domains` files into `work/blacklists`; nothing is written from archive paths."""
    lists = work / "blacklists"
    lists.mkdir(parents=True)
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            name = _list_name(member.name)
            if name is None:
                continue
            # UT1 has alias symlinks between list directories; a link in place of a list file is not trusted.
            if not member.isfile():
                raise ValueError(f"category list is not a regular file: {member.name!r}")
            target = lists / name / "domains"
            if target.exists():
                raise ValueError(f"category list appears twice in the archive: {name}")
            target.parent.mkdir()
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError(f"category list cannot be read: {member.name!r}")
            with source, target.open("wb") as output:
                while chunk := source.read(CHUNK):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"category lists exceed {max_bytes} bytes once extracted")
                    output.write(chunk)
    return lists


def update(archive: Path, output: Path, work: Path) -> dict[str, Any]:
    return build_categories(extract_lists(archive, work), output, now=datetime.now(UTC))


def run_periodically(job: Callable[[], object], interval_seconds: float, *,
                     sleep: Callable[[float], object] = time.sleep, rounds: int | None = None) -> None:
    """Run `job` forever (or `rounds` times); a failed round is reported and retried at the next interval."""
    completed = 0
    while True:
        try:
            job()
        except Exception as error:  # noqa: BLE001 - one failed refresh must not stop the daily job
            print(f"category update failed: {error}; the last publication stays in place", file=sys.stderr, flush=True)
        completed += 1
        if rounds is not None and completed >= rounds:
            return
        sleep(interval_seconds)


def _report(manifest: dict[str, Any]) -> int:
    for entry in manifest["categories"]:
        print(f"{entry['id']:12} {entry['count']:>9} domains  {entry['size'] / 1_048_576:7.1f} MB", flush=True)
    if not manifest["categories"]:
        print("no category lists found in the source", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", type=Path, metavar="PATH",
                        help="[source] output: UT1 blacklists directory, then the OPENEMS_CATEGORIES_DIR directory")
    parser.add_argument("--url", help="HTTPS address of the UT1 blacklists .tar.gz (replaces the source directory)")
    parser.add_argument("--every-hours", type=float, help="with --url: keep running and refresh at this interval")
    args = parser.parse_args()
    if args.url is not None:
        try:
            _require_https(args.url)
        except ValueError as error:
            parser.error(str(error))
        if len(args.paths) != 1:
            parser.error("with --url, give only the output directory")
        output = args.paths[0]

        def job() -> int:
            with tempfile.TemporaryDirectory(prefix="openems-ut1-") as scratch:
                downloaded = fetch_archive(args.url, Path(scratch) / "blacklists.tar.gz")
                return _report(update(downloaded, output, Path(scratch) / "work"))

        if args.every_hours is None:
            return job()
        if args.every_hours <= 0:
            parser.error("--every-hours must be positive")
        run_periodically(job, args.every_hours * 3600)
        return 0
    if args.every_hours is not None:
        parser.error("--every-hours requires --url")
    if len(args.paths) != 2:
        parser.error("give the source directory and the output directory")
    source, output = args.paths
    if not source.is_dir():
        parser.error(f"source directory not found: {source}")
    return _report(build_categories(source, output, now=datetime.now(UTC)))


if __name__ == "__main__":
    raise SystemExit(main())
