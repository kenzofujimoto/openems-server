#!/usr/bin/env python3
"""Enforce explicit skip and per-module coverage requirements in CI."""

from __future__ import annotations

import json
import sys
import defusedxml.ElementTree as ET
from pathlib import Path

CRITICAL = {
    "app/api.py", "app/auth.py", "app/recording.py", "app/replay.py",
    "app/saml.py", "app/saml_signatures.py", "agent/policy.py", "agent/openems_agent.py",
}
SERVICES = {
    "app/service.py", "app/stores.py", "app/idp_store.py", "app/queue.py",
    "app/audit.py", "agent/service.py",
}


def check(junit: Path, coverage: Path | None = None) -> list[str]:
    failures: list[str] = []
    root = ET.parse(junit).getroot()  # defusedxml refuses DTDs and entities in CI reports
    for suite in root.iter("testsuite"):
        for attribute in ("skipped", "errors", "failures"):
            count = int(suite.attrib.get(attribute, 0))
            if count:
                failures.append(f"{suite.attrib.get('name', 'tests')}: {count} {attribute}")
    if coverage is None:
        return failures
    report = json.loads(coverage.read_text(encoding="utf-8"))
    files = {name.replace("\\", "/"): data for name, data in report["files"].items()}
    failures.extend(f"{name}: coverage was not measured" for name in sorted(CRITICAL | SERVICES) if name not in files)
    for name, data in sorted(files.items()):
        threshold = 95 if name in CRITICAL else 90 if name in SERVICES else 80
        percent = float(data["summary"]["percent_covered"])
        if percent < threshold:
            failures.append(f"{name}: {percent:.2f}% coverage, requires {threshold}%")
    return failures


def main(arguments: list[str]) -> int:
    if not 1 <= len(arguments) <= 2:
        print("usage: python tools/check_quality.py <tests.junit.xml> [coverage.json]", file=sys.stderr)
        return 2
    try:
        failures = check(Path(arguments[0]), Path(arguments[1]) if len(arguments) == 2 else None)
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        print(f"Invalid quality report ({type(exc).__name__})", file=sys.stderr)
        return 2
    if failures:
        print("Quality gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("Quality gate passed: no skipped tests; measured modules meet their thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
