#!/usr/bin/env python3
"""Summarize an openems endpoint-channel capture (JSONL from app/recording.py).

Usage:
    python tools/analyze_capture.py capture.jsonl

Groups requests by (method, path), and for each shows the count, content-type,
the union of top-level JSON body keys, and one pretty-printed sample body — a
starting point for tightening SPEC-INTEROP.md §2 and the request models.
"""

from __future__ import annotations

import base64
import json
import sys
from collections import defaultdict
from typing import Any, Iterable


def load(path: str) -> Iterable[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def body_of(rec: dict[str, Any]) -> str:
    if "body_text" in rec:
        return rec["body_text"]
    if "body_b64" in rec:
        try:
            return base64.b64decode(rec["body_b64"]).decode("utf-8", "replace")
        except Exception:
            return "<binary>"
    return ""


def main(path: str) -> int:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for rec in load(path):
        groups[(rec.get("method", ""), rec.get("path", ""))].append(rec)

    if not groups:
        print("no requests found in", path)
        return 1

    for (method, p), recs in sorted(groups.items()):
        print(f"\n=== {method} {p}   ({len(recs)} request(s)) ===")
        print("content-type:", recs[0].get("content_type", "") or "(none)")
        keys: set[str] = set()
        sample: Any = None
        for r in recs:
            body = body_of(r)
            if body.strip().startswith(("{", "[")):
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        keys |= set(parsed.keys())
                    if sample is None:
                        sample = parsed
                except json.JSONDecodeError:
                    pass
            elif sample is None and body:
                sample = body[:400]
        if keys:
            print("json keys:", ", ".join(sorted(keys)))
        if sample is not None:
            rendered = (
                json.dumps(sample, indent=2, ensure_ascii=False)
                if not isinstance(sample, str)
                else sample
            )
            print("sample body:")
            print(rendered[:1500])
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python tools/analyze_capture.py <capture.jsonl>")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
