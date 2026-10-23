#!/usr/bin/env python3
"""Rebuild the published web categories from an extracted UT1 tree.

Fetch the lists first, for example:  git clone --depth 1 https://github.com/olbat/ut1-blacklists
Then:  python tools/update_categories.py ut1-blacklists/blacklists /var/lib/openems/categories
Run daily; agents pick up the new manifest at their next synchronization.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The repository root must be importable before the app package.
from app.categories import build_categories


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="UT1 blacklists directory (<list>/domains)")
    parser.add_argument("output", type=Path, help="directory served through OPENEMS_CATEGORIES_DIR")
    args = parser.parse_args()
    if not args.source.is_dir():
        parser.error(f"source directory not found: {args.source}")
    manifest = build_categories(args.source, args.output, now=datetime.now(UTC))
    for entry in manifest["categories"]:
        print(f"{entry['id']:12} {entry['count']:>9} domains  {entry['size'] / 1_048_576:7.1f} MB")
    if not manifest["categories"]:
        print("no category lists found under the source directory", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
